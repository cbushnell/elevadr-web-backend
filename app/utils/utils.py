import ipaddress

def convert_ips(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except:
        return int(ipaddress.IPv4Address(ip))