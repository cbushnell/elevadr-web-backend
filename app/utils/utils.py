import ipaddress

def convert_ips(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        return int(ipaddress.IPv6Address(ip))