#implement ceaser cypher
import socket
import os
import sys
import threading
from binascii import hexlify
from scapy.all import *


def ceaser(text, shift):
    """
    :param text: string
    :param shift: int
    :return: string
    """
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

def main(dst, dport):
    #get user input
    text = input("Enter text to encrypt: ")
    shift = int(input("Enter shift: "))
    
    #encrypt text
    cyphertext = ceaser(text, shift)
    
    #print cyphertext
    print("Encrypted text: " + cyphertext)
    print("Decrypted text: " + ceaser(cyphertext, -shift))


    for car in cyphertext:
        # create UDP packet
        testchksum = int(hexlify(car.encode()), 16)
        packet =  (Ether(dst="34:c9:3d:23:12:d4")/ IP(dst=dst) / UDP(sport=42069,dport=20000, chksum=testchksum) / Raw(load=str(shift).encode()))
    
    #show packet
    # print(packet.show())

    # send packet
        sendp(packet, iface="Ethernet 2")
    # t.join()

if __name__ == '__main__':
    dst = sys.argv[1]
    dport = int(sys.argv[2])
    main(dst, dport)