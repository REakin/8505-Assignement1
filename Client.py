from itertools import count
from struct import pack
import scapy
import os
import sys
import threading
from scapy.all import *
import datetime

import tkinter as tk
from tkinter import ttk 


class UI(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.start()

    def run(self):
        self.root = tk.Tk()
        self.root.title("Covert Channel Client")
        self.root.geometry("800x400")
        self.root.resizable(0,0)
        self.root.configure(background='#FFFFFF')
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)


        #create widget
        self.packet_info = tk.Frame(self.root, bg='#FFFFFF')
        self.packet_info.grid(row=0, column=0, sticky='nsew')
        self.packet_info.grid_columnconfigure(0, weight=1)
        self.packet_info.grid_rowconfigure(0, weight=1)

        #message widget
        self.messageWidget = tk.Frame(self.root, bg='#E0E0E0')
        self.messageWidget.grid(row=1, column=0, sticky='nsew')
        self.messageWidget.grid_columnconfigure((0,1), weight=1, uniform="column")
        self.messageWidget.grid_rowconfigure(1, weight=1)

        #create treeview
        self.tree = tk.ttk.Treeview(self.packet_info, columns=('Time', 'Source', 'Source Port', 'Checksum', 'Length'))
        self.tree.heading('#0', text='Time')
        self.tree.heading('#1', text='Source')
        self.tree.heading('#2', text='Source Port')
        self.tree.heading('#3', text='CheckSum')
        self.tree.heading('#4', text='Length')
        self.tree.grid(row=0, column=0, sticky='nsew')

        #create scrollbar
        self.scrollbar = tk.Scrollbar(self.packet_info, orient="vertical", command=self.tree.yview, bg='#E0E0E0')
        self.scrollbar.grid(row=0, column=1, sticky='nsew')
        #configure treeview
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.tree.column('#0', width=200, stretch=False)
        self.tree.column('#1', width=200, stretch=False)
        self.tree.column('#2', width=140, stretch=False)
        self.tree.column('#3', width=140, stretch=False)
        self.tree.column('#4', width=100, stretch=False)
        # self.tree.bind('<Double-1>', self.on_double_click)
        
        #create message
        self.message = tk.Text(self.messageWidget, height=5)
        self.message.grid(row=0, column=0, columnspan=2, sticky='nsew')
        self.message.configure(state='disabled')
        self.message.configure(background='#E0E0E0')

        #create save button
        self.save_button = tk.Button(self.messageWidget, text='Save', command=self.save_message)
        self.save_button.grid(row=1, column=0, sticky='nsew')

        #create clear button
        self.clear_button = tk.Button(self.messageWidget, text='Clear', command=self.clear_message)
        self.clear_button.grid(row=1, column=1, sticky='nsew')

        #main loop
        self.root.mainloop()

    def add_packet(self, packet):
        chksum = packet.chksum
        src = packet.src
        time = datetime.datetime.fromtimestamp(packet.time)
        length = len(packet.payload.load)
        sport = packet.sport
        self.tree.insert('', 'end', values=(time, src, sport, chksum, length))

    def clear_message(self):
        self.message.configure(state='normal')
        self.message.delete('1.0', 'end')
        self.message.configure(state='disabled')
    
    def save_message(self):
        self.message.configure(state='normal')
        text = self.message.get('1.0', 'end')
        self.message.delete('1.0', 'end')
        self.message.configure(state='disabled')
        # save to file
        tim = datetime.datetime.now()
        with open(str(tim.timestamp())+".txt", 'w') as f:
            f.write(text)
            f.close()
        

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

def packet_callback(packet, ui):
    if packet[UDP].dport == 20000:
        # print("[+] Received encrypted message: " + (packet[Raw].load).decode())
        #extract the checksum
        checksum = chr(packet[UDP].chksum)
        # print("[+] Checksum: " + str(checksum))
        #extract the shift
        shift = (packet[Raw].load).decode()
        shift == len(shift)

        #decrypt the message
        decoded_message = ceaser(checksum, -int(shift))
        
        #update the UI
        ui.add_packet(packet)
        ui.message.configure(state='normal')
        ui.message.insert('end', decoded_message)
        ui.message.configure(state='disabled')

def main():
    #create the UI
    ui = UI()
    #sniff packets
    print("[+] Sniffing for encrypted messages...")
    #sniff packets on loopback interface
    sniff(iface="Wi-Fi", filter="udp", prn=lambda x: packet_callback(x,ui), count=0)


if __name__ == '__main__':
    main()