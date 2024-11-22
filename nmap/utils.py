def convert_nmap_output_to_encoding(value: dict, code: str = "ascii"):
    """
    Change encoding for scan_result object from unicode to whatever

    :param value: scan_result as dictionnary
    :param code: default = "ascii", encoding destination

    :returns: scan_result as dictionnary with new encoding
    """
    new_value = {}
    for k in value:
        if isinstance(value[k], dict):
            new_value[k] = convert_nmap_output_to_encoding(value[k], code)
        else:
            if isinstance(value[k], list):
                new_value[k] = [
                    convert_nmap_output_to_encoding(x, code) for x in value[k]
                ]
            else:
                new_value[k] = value[k].encode(code)
    return new_value
