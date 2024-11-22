import asyncio
import contextlib
import csv
import io
import os
import re
import shlex
import sys
from asyncio.subprocess import Process
from typing import Any
from xml.etree import ElementTree

from nmap.host_dict import HostDict
from nmap.errors import PortScannerError

NMAP_SEARCH_PATH = (
    "nmap",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/sw/bin/nmap",
    "/opt/local/bin/nmap",
)
NMAP_REGEX = re.compile(r"Nmap version [0-9]*\.[0-9]*[^ ]* \( http(|s)://.* \)")
IS_LINUX_MACOS = (
    sys.platform.startswith("freebsd")
    or sys.platform.startswith("linux")
    or sys.platform.startswith("darwin")
)


class PortScanner:
    def __init__(self, nmap_search_path: tuple[str] = NMAP_SEARCH_PATH) -> None:
        self._nmap_path = ""
        self._scan_result = {}
        self._nmap_version_number = 0
        self._nmap_subversion_number = 0
        self._nmap_last_output = ""
        self.is_nmap_found = False
        self.nmap_search_path = nmap_search_path
        self.__process = None

    async def async_init(self) -> None:
        self._nmap_last_output = await self.get_nmap_version(self.nmap_search_path)
        for line in self._nmap_last_output.split(os.linesep):
            if NMAP_REGEX.match(line) is None:
                continue

            self.is_nmap_found = True
            regex_version = re.compile("[0-9]+")
            regex_subversion = re.compile(r"\.[0-9]+")

            rv = regex_version.search(line)
            rsv = regex_subversion.search(line)

            if rv is not None and rsv is not None:
                self._nmap_version_number = int(line[rv.start() : rv.end()])
                self._nmap_subversion_number = int(line[rsv.start() + 1 : rsv.end()])
            break

        if not self.is_nmap_found:
            raise PortScannerError("nmap program was not found in path")

    @staticmethod
    async def open_subprocess(path, *args: Any, **kwargs: Any) -> Process:
        return await asyncio.subprocess.create_subprocess_exec(
            path,
            *args,
            **kwargs,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def get_nmap_version(self, search_path: tuple[str]) -> str:
        for nmap_path in search_path:
            with contextlib.suppress(OSError):
                p = await self.open_subprocess(
                    nmap_path,
                    "-V",
                    close_fds=IS_LINUX_MACOS,
                )
                self._nmap_path = nmap_path
                return bytes.decode((await p.communicate())[0])

        raise PortScannerError("nmap program was not found in path.")

    def get_nmap_last_output(self) -> str:
        return self._nmap_last_output

    def nmap_version(self) -> tuple[int, int]:
        return self._nmap_version_number, self._nmap_subversion_number

    async def listscan(self, hosts: str = "127.0.0.1"):
        output = await self.scan(hosts, arguments="-sL")
        # Test if host was IPV6
        if (
            "scaninfo" in output["nmap"]
            and "error" in output["nmap"]["scaninfo"]
            and len(output["nmap"]["scaninfo"]["error"]) > 0
            and "looks like an IPv6 target specification"
            in output["nmap"]["scaninfo"]["error"][0]
        ):
            await self.scan(hosts, arguments="-sL -6")

        return self.all_hosts()

    async def scan(  # NOQA: CFQ001, C901
        self,
        hosts: str = "127.0.0.1",
        ports: str = None,
        arguments: str = "-sV",
        sudo: bool = False,
    ):
        """
        Scan given hosts

        May raise PortScannerError exception if nmap output was not xml

        Test existance of the following key to know
        if something went wrong : ['nmap']['scaninfo']['error']
        If not present, everything was ok.

        :param hosts: string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as nmap use it '22,53,110,143-4564'
        :param arguments: string of arguments for nmap '-sU -sX -sC'
        :param sudo: launch nmap with sudo if True

        :returns: scan_result as dictionnary
        """
        for redirecting_output in ["-oX", "-oA"]:
            assert (
                redirecting_output not in arguments
            ), "Xml output can't be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()"  # noqa

        h_args = shlex.split(hosts)
        f_args = shlex.split(arguments)

        path = self._nmap_path
        args = ["-oX", "-"] + h_args + ["-p", ports] * (ports is not None) + f_args
        if sudo:
            args = ["sudo"] + args

        p = await self.open_subprocess(path, *args)
        self._nmap_last_output, nmap_err = await p.communicate()
        nmap_err = bytes.decode(nmap_err)

        # If there was something on stderr, there was a problem so abort...  in
        # fact not always. As stated by AlenLPeacock :
        # This actually makes python-nmap mostly unusable on most real-life
        # networks -- a particular subnet might have dozens of scannable hosts,
        # but if a single one is unreachable or unroutable during the scan,
        # nmap.scan() returns nothing. This behavior also diverges significantly
        # from commandline nmap, which simply stderrs individual problems but
        # keeps on trucking.

        nmap_err_keep_trace = []
        nmap_warn_keep_trace = []
        if len(nmap_err) > 0:
            regex_warning = re.compile("^Warning: .*", re.IGNORECASE)
            for line in nmap_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        nmap_warn_keep_trace.append(line + os.linesep)
                    else:
                        nmap_err_keep_trace.append(nmap_err)

        return self.analyse_nmap_xml_scan(
            nmap_xml_output=self._nmap_last_output,
            nmap_err=nmap_err,
            nmap_err_keep_trace=nmap_err_keep_trace,
            nmap_warn_keep_trace=nmap_warn_keep_trace,
        )

    def analyse_nmap_xml_scan(  # NOQA: CFQ001, C901
        self,
        nmap_xml_output=None,
        nmap_err: str = "",
        nmap_err_keep_trace: list[str] = None,
        nmap_warn_keep_trace: list[str] = None,
    ):
        """
        Analyses NMAP xml scan ouput

        May raise PortScannerError exception if nmap output was not xml

        Test existance of the following key to know if something went wrong : ['nmap']['scaninfo']['error']
        If not present, everything was ok.

        :param nmap_xml_output: xml string to analyse
        :returns: scan_result as dictionnary
        """
        if nmap_xml_output is not None:
            self._nmap_last_output = nmap_xml_output

        scan_result = {}

        try:
            dom = ElementTree.fromstring(self._nmap_last_output)
        except Exception:
            if len(nmap_err) > 0:
                raise PortScannerError(nmap_err)
            else:
                raise PortScannerError(self._nmap_last_output)

        # nmap command line
        scan_result["nmap"] = {
            "command_line": dom.get("args"),
            "scaninfo": {},
            "scanstats": {
                "timestr": dom.find("runstats/finished").get("timestr"),
                "elapsed": dom.find("runstats/finished").get("elapsed"),
                "uphosts": dom.find("runstats/hosts").get("up"),
                "downhosts": dom.find("runstats/hosts").get("down"),
                "totalhosts": dom.find("runstats/hosts").get("total"),
            },
        }

        # if there was an error
        if len(nmap_err_keep_trace) > 0:
            scan_result["nmap"]["scaninfo"]["error"] = nmap_err_keep_trace

        # if there was a warning
        if len(nmap_warn_keep_trace) > 0:
            scan_result["nmap"]["scaninfo"]["warning"] = nmap_warn_keep_trace

        # info about scan
        for dsci in dom.findall("scaninfo"):
            scan_result["nmap"]["scaninfo"][dsci.get("protocol")] = {
                "method": dsci.get("type"),
                "services": dsci.get("services"),
            }

        scan_result["scan"] = {}

        for dhost in dom.findall("host"):
            # host ip, mac and other addresses
            host = None
            address_block = {}
            vendor_block = {}
            for address in dhost.findall("address"):
                addtype = address.get("addrtype")
                address_block[addtype] = address.get("addr")
                if addtype == "ipv4":
                    host = address_block[addtype]
                elif addtype == "mac" and address.get("vendor") is not None:
                    vendor_block[address_block[addtype]] = address.get("vendor")

            if host is None:
                host = dhost.find("address").get("addr")

            hostnames = []
            if len(dhost.findall("hostnames/hostname")) > 0:
                for dhostname in dhost.findall("hostnames/hostname"):
                    hostnames.append(
                        {"name": dhostname.get("name"), "type": dhostname.get("type")}
                    )
            else:
                hostnames.append({"name": "", "type": ""})

            scan_result["scan"][host] = HostDict({"hostnames": hostnames})

            scan_result["scan"][host]["addresses"] = address_block
            scan_result["scan"][host]["vendor"] = vendor_block

            for dstatus in dhost.findall("status"):
                # status : up...
                scan_result["scan"][host]["status"] = {
                    "state": dstatus.get("state"),
                    "reason": dstatus.get("reason"),
                }
            for dstatus in dhost.findall("uptime"):
                # uptime : seconds, lastboot
                scan_result["scan"][host]["uptime"] = {
                    "seconds": dstatus.get("seconds"),
                    "lastboot": dstatus.get("lastboot"),
                }
            for dport in dhost.findall("ports/port"):
                # protocol
                proto = dport.get("protocol")
                # port number converted as integer
                port = int(dport.get("portid"))
                # state of the port
                state = dport.find("state").get("state")
                # reason
                reason = dport.find("state").get("reason")
                # name, product, version, extra info and conf if any
                name = product = version = extrainfo = conf = cpe = ""
                for dname in dport.findall("service"):
                    name = dname.get("name")
                    if dname.get("product"):
                        product = dname.get("product")
                    if dname.get("version"):
                        version = dname.get("version")
                    if dname.get("extrainfo"):
                        extrainfo = dname.get("extrainfo")
                    if dname.get("conf"):
                        conf = dname.get("conf")

                    for dcpe in dname.findall("cpe"):
                        cpe = dcpe.text
                # store everything
                if proto not in list(scan_result["scan"][host].keys()):
                    scan_result["scan"][host][proto] = {}

                scan_result["scan"][host][proto][port] = {
                    "state": state,
                    "reason": reason,
                    "name": name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "conf": conf,
                    "cpe": cpe,
                }
                script_id = ""
                script_out = ""
                # get script output if any
                for dscript in dport.findall("script"):
                    script_id = dscript.get("id")
                    script_out = dscript.get("output")
                    if "script" not in list(
                        scan_result["scan"][host][proto][port].keys()
                    ):
                        scan_result["scan"][host][proto][port]["script"] = {}

                    scan_result["scan"][host][proto][port]["script"][
                        script_id
                    ] = script_out

            # <hostscript>
            #  <script id="nbstat" output="NetBIOS name: GROSTRUC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: &lt;unknown&gt;&#xa;" />  # NOQA: E501
            #  <script id="smb-os-discovery" output=" &#xa;  OS: Unix (Samba 3.6.3)&#xa;  Name: WORKGROUP\Unknown&#xa;  System time: 2013-06-23 15:37:40 UTC+2&#xa;" />  # NOQA: E501
            #  <script id="smbv2-enabled" output="Server doesn&apos;t support SMBv2 protocol" />
            # </hostscript>
            for dhostscript in dhost.findall("hostscript"):
                for dname in dhostscript.findall("script"):
                    hsid = dname.get("id")
                    hsoutput = dname.get("output")

                    if "hostscript" not in list(scan_result["scan"][host].keys()):
                        scan_result["scan"][host]["hostscript"] = []

                    scan_result["scan"][host]["hostscript"].append(
                        {"id": hsid, "output": hsoutput}
                    )

            # <osmatch name="Juniper SA4000 SSL VPN gateway (IVE OS 7.0)" accuracy="98" line="36241">
            # <osclass type="firewall" vendor="Juniper" osfamily="IVE OS" osgen="7.X"
            # accuracy="98"><cpe>cpe:/h:juniper:sa4000</cpe><cpe>cpe:/o:juniper:ive_os:7</cpe></osclass>
            # </osmatch>
            # <osmatch name="Cymphonix EX550 firewall" accuracy="98" line="17929">
            # <osclass type="firewall" vendor="Cymphonix" osfamily="embedded"
            # accuracy="98"><cpe>cpe:/h:cymphonix:ex550</cpe></osclass>
            # </osmatch>
            for dos in dhost.findall("os"):
                osmatch = []
                portused = []
                for dportused in dos.findall("portused"):
                    # <portused state="open" proto="tcp" portid="443"/>
                    state = dportused.get("state")
                    proto = dportused.get("proto")
                    portid = dportused.get("portid")
                    portused.append({"state": state, "proto": proto, "portid": portid})

                scan_result["scan"][host]["portused"] = portused

                for dosmatch in dos.findall("osmatch"):
                    # <osmatch name="Linux 3.7 - 3.15" accuracy="100" line="52790">
                    name = dosmatch.get("name")
                    accuracy = dosmatch.get("accuracy")
                    line = dosmatch.get("line")

                    osclass = []
                    for dosclass in dosmatch.findall("osclass"):
                        # <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="98"/>
                        ostype = dosclass.get("type")
                        vendor = dosclass.get("vendor")
                        osfamily = dosclass.get("osfamily")
                        osgen = dosclass.get("osgen")
                        accuracy = dosclass.get("accuracy")

                        cpe = []
                        for dcpe in dosclass.findall("cpe"):
                            cpe.append(dcpe.text)

                        osclass.append(
                            {
                                "type": ostype,
                                "vendor": vendor,
                                "osfamily": osfamily,
                                "osgen": osgen,
                                "accuracy": accuracy,
                                "cpe": cpe,
                            }
                        )

                    osmatch.append(
                        {
                            "name": name,
                            "accuracy": accuracy,
                            "line": line,
                            "osclass": osclass,
                        }
                    )
                else:
                    scan_result["scan"][host]["osmatch"] = osmatch

            for dport in dhost.findall("osfingerprint"):
                # <osfingerprint fingerprint="OS:SCAN(V=5.50%D=11/[...]S)&#xa;"/>
                fingerprint = dport.get("fingerprint")

                scan_result["scan"][host]["fingerprint"] = fingerprint

        self._scan_result = scan_result  # store for later use
        return scan_result

    def __getitem__(self, host):
        """
        returns a host detail
        """
        if sys.version_info[0] == 2:
            assert type(host) in (
                str,
            ), f"Wrong type for [host], should be a string [was {type(host)}]"
        else:
            assert (
                type(host) is str
            ), f"Wrong type for [host], should be a string [was {type(host)}]"
        return self._scan_result["scan"][host]

    def all_hosts(self):
        """
        returns a sorted list of all hosts
        """
        if "scan" not in list(self._scan_result.keys()):
            return []
        listh = list(self._scan_result["scan"].keys())
        listh.sort()
        return listh

    def command_line(self):
        """
        returns command line used for the scan

        may raise AssertionError exception if called before scanning
        """
        assert "nmap" in self._scan_result, "Do a scan before trying to get result"
        assert (
            "command_line" in self._scan_result["nmap"]
        ), "Do a scan before trying to get result"

        return self._scan_result["nmap"]["command_line"]

    def scaninfo(self):
        """
        returns scaninfo structure
        {'tcp': {'services': '22', 'method': 'connect'}}

        may raise AssertionError exception if called before scanning
        """
        assert "nmap" in self._scan_result, "Do a scan before trying to get result"
        assert (
            "scaninfo" in self._scan_result["nmap"]
        ), "Do a scan before trying to get result"

        return self._scan_result["nmap"]["scaninfo"]

    def scanstats(self):
        """
        returns scanstats structure
        {'uphosts': '3', 'timestr': 'Thu Jun  3 21:45:07 2010', 'downhosts': '253', 'totalhosts': '256', 'elapsed': '5.79'}  # NOQA: E501

        may raise AssertionError exception if called before scanning
        """
        assert "nmap" in self._scan_result, "Do a scan before trying to get result"
        assert (
            "scanstats" in self._scan_result["nmap"]
        ), "Do a scan before trying to get result"

        return self._scan_result["nmap"]["scanstats"]

    def has_host(self, host):
        """
        returns True if host has result, False otherwise
        """
        assert (
            type(host) is str
        ), f"Wrong type for [host], should be a string [was {type(host)}]"
        assert "scan" in self._scan_result, "Do a scan before trying to get result"

        if host in list(self._scan_result["scan"].keys()):
            return True

        return False

    def csv(self):
        """
        returns CSV output as text

        Example :
        host;hostname;hostname_type;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe
        127.0.0.1;localhost;PTR;tcp;22;ssh;open;OpenSSH;protocol 2.0;syn-ack;5.9p1 Debian 5ubuntu1;10;cpe
        127.0.0.1;localhost;PTR;tcp;23;telnet;closed;;;conn-refused;;3;
        127.0.0.1;localhost;PTR;tcp;24;priv-mail;closed;;;conn-refused;;3;
        """
        assert "scan" in self._scan_result, "Do a scan before trying to get result"

        fd = io.StringIO()
        csv_ouput = csv.writer(fd, delimiter=";")
        csv_header = [
            "host",
            "hostname",
            "hostname_type",
            "protocol",
            "port",
            "name",
            "state",
            "product",
            "extrainfo",
            "reason",
            "version",
            "conf",
            "cpe",
        ]

        csv_ouput.writerow(csv_header)

        for host in self.all_hosts():
            for proto in self[host].all_protocols():
                if proto not in ["tcp", "udp"]:
                    continue
                lport = list(self[host][proto].keys())
                lport.sort()
                for port in lport:
                    for h in self[host]["hostnames"]:
                        hostname = h["name"]
                        hostname_type = h["type"]
                        csv_row = [
                            host,
                            hostname,
                            hostname_type,
                            proto,
                            port,
                            self[host][proto][port]["name"],
                            self[host][proto][port]["state"],
                            self[host][proto][port]["product"],
                            self[host][proto][port]["extrainfo"],
                            self[host][proto][port]["reason"],
                            self[host][proto][port]["version"],
                            self[host][proto][port]["conf"],
                            self[host][proto][port]["cpe"],
                        ]
                        csv_ouput.writerow(csv_row)

        return fd.getvalue()
