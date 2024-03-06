from scapy.all import *
import sys

from scapy.layers.inet import ICMP, UDP, TCP, IP
from scapy.layers.l2 import Ether, ARP


def arp_ping_scan(ip_range):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=2)
    for snd, rcv in ans:
        print(rcv.sprintf(r"%ARP.psrc% - %Ether.src%"))


def icmp_ping_scan(ip_range):
    ans, unans = sr(IP(dst=ip_range) / ICMP(), timeout=2)
    for snd, rcv in ans:
        print(rcv.sprintf(r"%IP.src%"))


def icmp_ping_sweep(ip_range):
    ans, unans = sr(IP(dst=ip_range) / ICMP(), timeout=2)
    for snd, rcv in ans:
        print(rcv.sprintf(r"%IP.src% is alive"))


def icmp_timestamp_ping(ip_addr):
    ans = sr1(IP(dst=ip_addr) / ICMP(type=13, code=0), timeout=2, verbose=0)
    if ans:
        print(f"{ip_addr} is alive")
    else:
        print(f"{ip_addr} is down")


def icmp_address_mask_ping(ip_addr):
    ans = sr1(IP(dst=ip_addr) / ICMP(type=17, code=0), timeout=2, verbose=0)
    if ans:
        print(f"{ip_addr} is alive, and the address mask is {ans.payload.payload.mask}")
    else:
        print(f"{ip_addr} is down")


def udp_ping_scan(ip_range, port):
    ans, unans = sr(IP(dst=ip_range) / UDP(dport=port), timeout=2)
    for snd, rcv in ans:
        print(rcv.sprintf(r"%IP.src% is alive"))


def tcp_syn_scan(ip_range, port):
    ans, unans = sr(IP(dst=ip_range) / TCP(dport=port, flags="S"), timeout=2)
    for snd, rcv in ans:
        print(rcv.sprintf(r"%IP.src% %TCP.sport% is open"))


def tcp_ack_scan(ip_addr, port):
    ans = sr1(IP(dst=ip_addr) / TCP(dport=port, flags="A"), timeout=2, verbose=0)
    if ans and ans.haslayer(TCP):
        if ans[TCP].flags == "R":
            print(f"{ip_addr}:{port} is open")
        else:
            print(f"{ip_addr}:{port} is closed")
    else:
        print(f"{ip_addr}:{port} is filtered")


def tcp_null_scan(ip_addr, port):
    ans = sr1(IP(dst=ip_addr) / TCP(dport=port, flags=""), timeout=2, verbose=0)
    if ans and ans.haslayer(TCP):
        if ans[TCP].flags == "R":
            print(f"{ip_addr}:{port} is open")
        else:
            print(f"{ip_addr}:{port} is closed")
    else:
        print(f"{ip_addr}:{port} is filtered")


def tcp_xmas_scan(ip_addr, port):
    # TCP XMAS Scan (Does not work on Windows)
    ans = sr1(IP(dst=ip_addr) / TCP(dport=port, flags="FPU"), timeout=2, verbose=0)
    if ans and ans.haslayer(TCP):
        if ans[TCP].flags == "R":
            print(f"{ip_addr}:{port} is open")
        else:
            print(f"{ip_addr}:{port} is closed")
    else:
        print(f"{ip_addr}:{port} is filtered")


def tcp_fin_scan(ip_addr, port):
    ans = sr1(IP(dst=ip_addr) / TCP(dport=port, flags="F"), timeout=2, verbose=0)
    if ans and ans.haslayer(TCP):
        if ans[TCP].flags == "R":
            print(f"{ip_addr}:{port} is open")
        else:
            print(f"{ip_addr}:{port} is closed")
    else:
        print(f"{ip_addr}:{port} is filtered")


def ip_protocol_ping_scan(ip_addr, protocols):
    for protocol in protocols:
        ans = sr1(IP(dst=ip_addr, proto=protocol), timeout=2, verbose=0)
        if ans:
            print(f"{ip_addr} is alive for protocol {protocol}")
        else:
            print(f"{ip_addr} is down for protocol {protocol}")


def main():
    print("Welcome to the Host Discovery Tool")
    print("Please select an option:")
    print("1. ARP Ping Scan")
    print("2. ICMP Ping Scan")
    print("3. UDP Ping Scan")
    print("4. TCP Ping Scan")
    print("5. IP Protocol Ping Scan")
    choice = input("Enter your choice (1-5): ")

    if choice == "1":
        ip_range = input("Enter IP range (e.g., 192.168.1.0/24): ")
        arp_ping_scan(ip_range)
    elif choice == "2":
        print("ICMP Ping Scan options:")
        print("a. ICMP Echo Ping")
        print("b. ICMP Echo Ping Sweep")
        print("c. ICMP Timestamp Ping")
        print("d. ICMP Address Mask Ping")
        option = input("Enter option (a-d): ")
        ip_addr = input("Enter IP address or range: ")
        if option == "a":
            icmp_ping_scan(ip_addr)
        elif option == "b":
            icmp_ping_sweep(ip_addr)
        elif option == "c":
            icmp_timestamp_ping(ip_addr)
        elif option == "d":
            icmp_address_mask_ping(ip_addr)
    elif choice == "3":
        ip_range = input("Enter IP range (e.g., 192.168.1.0/24): ")
        port = int(input("Enter port number: "))
        udp_ping_scan(ip_range, port)
    elif choice == "4":
        print("TCP Ping Scan options:")
        print("a. TCP SYN Scan")
        print("b. TCP ACK Scan")
        print("c. TCP Null Scan")
        print("d. TCP XMAS Scan (Does not work on Windows)")
        print("e. TCP FIN Scan")
        option = input("Enter option (a-e): ")
        ip_addr = input("Enter IP address or range: ")
        port = int(input("Enter port number: "))
        if option == "a":
            tcp_syn_scan(ip_addr, port)
        elif option == "b":
            tcp_ack_scan(ip_addr, port)
        elif option == "c":
            tcp_null_scan(ip_addr, port)
        elif option == "d":
            tcp_xmas_scan(ip_addr, port)
        elif option == "e":
            tcp_fin_scan(ip_addr, port)
    elif choice == "5":
        ip_addr = input("Enter IP address: ")
        protocols = input("Enter protocols (e.g., 1,6,17 for ICMP, TCP, UDP): ").split(",")
        protocols = [int(p) for p in protocols]
        ip_protocol_ping_scan(ip_addr, protocols)
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    main()
