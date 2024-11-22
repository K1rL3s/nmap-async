class HostDict(dict):
    """
    Special dictionnary class for storing and accessing host scan result

    """

    def hostnames(self):
        """
        :returns: list of hostnames

        """
        return self["hostnames"]

    def hostname(self):
        """
        For compatibility purpose...
        :returns: try to return the user record or the first hostname of the list hostnames

        """
        for h in self["hostnames"]:
            if h["type"] == "user":
                return h["name"]
        else:
            if len(self["hostnames"]) > 0 and "name" in self["hostnames"][0]:
                return self["hostnames"][0]["name"]
            return ""

    def state(self):
        return self["status"]["state"]

    def uptime(self):
        return self["uptime"]

    def all_protocols(self):
        def _proto_filter(x):
            return x in ["ip", "tcp", "udp", "sctp"]

        lp = list(filter(_proto_filter, list(self.keys())))
        lp.sort()
        return lp

    def all_tcp(self) -> list:
        return sorted(list(self.get("tcp", {}).keys()))

    def has_tcp(self, port: int) -> bool:
        return "tcp" in self.get("tcp", {})

    def tcp(self, port: int) -> bool:
        return self["tcp"][port]

    def all_udp(self) -> list:
        return sorted(list(self.get("udp", {}).keys()))

    def has_udp(self, port: int) -> bool:
        return "udp" in self.get("udp", {})

    def udp(self, port: int):
        return self["udp"][port]

    def all_ip(self):
        return sorted(list(self.get("ip", {}).keys()))

    def has_ip(self, port: int) -> bool:
        return port in self.get("ip", {})

    def ip(self, port: int):
        return self["ip"][port]

    def all_sctp(self) -> list:
        return sorted(list(self.get("scpt", {}).keys()))

    def has_sctp(self, port: int) -> bool:
        return "scpt" in self.get("sctp", {})

    def sctp(self, port: bool):
        return self["sctp"][port]
