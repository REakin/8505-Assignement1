#implement ceaser cypher
import socket
import os
import sys
import threading
from binascii import hexlify
from scapy.all import *
import tkinter as tk

#create UI
class UI(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.start()
    def run(self):
        self.root = tk.Tk()
        self.root.title("Covert Channel Client")
        self.root.resizable(0,0)
        self.root.configure(background='#FFFFFF')

        self.input_frame = tk.Frame(self.root, bg='#FFFFFF')
        self.input_frame.grid(row=0, column=0, sticky='nsew')
        self.input_frame.grid_columnconfigure(0, weight=1)
        self.input_frame.grid_rowconfigure(0, weight=1)

        #create input field
        self.ip_label = tk.Label(self.input_frame, text="IP:", bg='#FFFFFF')
        self.ip_label.grid(row=0, column=0, sticky='nsew')
        self.ip_field = tk.Entry(self.input_frame, width=50)
        self.ip_field.grid(row=0, column=1, sticky='nsew')

        #create MAC field
        self.mac_label = tk.Label(self.input_frame, text="MAC:", bg='#FFFFFF')
        self.mac_label.grid(row=1, column=0, sticky='nsew')
        self.mac_field = tk.Entry(self.input_frame, width=50)
        self.mac_field.grid(row=1, column=1, sticky='nsew')

        #create shift field
        self.shift_label = tk.Label(self.input_frame, text="Shift:", bg='#FFFFFF')
        self.shift_label.grid(row=2, column=0, sticky='nsew')
        self.shift_field = tk.Entry(self.input_frame, width=50)
        self.shift_field.grid(row=2, column=1, sticky='nsew')

        #create port field
        self.port_label = tk.Label(self.input_frame, text="Port:", bg='#FFFFFF')
        self.port_label.grid(row=3, column=0, sticky='nsew')
        self.port_field = tk.Entry(self.input_frame, width=50)
        self.port_field.grid(row=3, column=1, sticky='nsew')

        #create message field
        self.message_label = tk.Label(self.input_frame, text="Message:", bg='#FFFFFF')
        self.message_label.grid(row=4, column=0, sticky='nsew')
        self.message_field = tk.Entry(self.input_frame, width=50)
        self.message_field.grid(row=4, column=1, sticky='nsew')

        #create send button
        self.send_button = tk.Button(self.root, text="Send", command=self.send_button_clicked)
        self.send_button.grid(row=1, column=0, sticky='nsew')

        self.root.mainloop()

    def send_button_clicked(self):
        self.ip = str(self.ip_field.get())
        self.mac = self.mac_field.get()
        self.shift = self.shift_field.get()
        self.port = self.port_field.get()
        self.message = self.message_field.get()
        #clear message field
        self.message_field.delete(0, 'end')

        self.send_packets(self.ip, self.mac, self.shift, self.port, self.message)
    
    def send_packets(self, ip, mac, shift, port, message):
        #create packet
        cyphertext = ceaser(message, int(shift))
        for car in cyphertext:
            # create UDP packet
            testchksum = int(hexlify(car.encode()), 16)
            #create an string the length of shift
            payload = ''.join(['\x00'] * int(shift))
            packet =  (Ether(dst=mac)/ IP(dst=ip) / UDP(sport=42069, dport=int(port), chksum=testchksum) / Raw(load=payload))
            #send packet
            sendp(packet, verbose=0)
        tk.messagebox.showinfo("Sent", "Sent packets to " + ip)
        

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

def main():
    ui = UI()
    ui.join()
    # #get user input
    # text = input("Enter text to encrypt: ")
    # shift = int(input("Enter shift: "))
    
    # #encrypt text
    # cyphertext = ceaser(text, shift)
    
    # #print cyphertext
    # print("Encrypted text: " + cyphertext)
    # print("Decrypted text: " + ceaser(cyphertext, -shift))


    # for car in cyphertext:
    #     # create UDP packet
    #     testchksum = int(hexlify(car.encode()), 16)
    #     packet =  (Ether(dst="34:c9:3d:23:12:d4")/ IP(dst=dst) / UDP(sport=42069,dport=20000, chksum=testchksum) / Raw(load=str(shift).encode()))
    
    #show packet
    # print(packet.show())

    # send packet
        # sendp(packet, iface="Ethernet 2")
    # t.join()

if __name__ == '__main__':
    # dst = sys.argv[1]
    # dport = int(sys.argv[2])
    main()