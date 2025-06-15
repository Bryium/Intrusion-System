from scapy.all import get_if_list, get_if_hwaddr

for iface in get_if_list():
    try:
        print(f"{iface} - {get_if_hwaddr(iface)}")
    except:
        print(f"{iface} - Unable to get MAC")
