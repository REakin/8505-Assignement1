from itertools import count
import scapy
import os
import sys
import threading
from scapy.all import *

def ceaser(text, shift):
    cyphertext = ''
    for char in text:
        if char.isalpha():
            if char.isupper():
                cyphertext += chr((ord(char) + shift - 65) % 26 + 65)
            else:
                cyphertext += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            cyphertext += char
    return cyphertext

def packet_callback(packet):
    if packet[UDP].dport == 20000:
        print("[+] Received encrypted message: " + packet[Raw].load)
        print("[+] Decrypted message: " + ceaser(packet[Raw].load, -shift))

def main():
    #sniff packets
    print("[+] Sniffing for encrypted messages...")
    #sniff packets on loopback interface
    sniff(iface="Ethernet 2", filter="udp", prn=lambda x: packet_callback(x), count=0)


if __name__ == '__main__':
    main()