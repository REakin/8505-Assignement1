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
        self.random = tk.IntVar()
        
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

        #create shift field
        self.shift_label = tk.Label(self.input_frame, text="Shift:", bg='#FFFFFF')
        self.shift_label.grid(row=2, column=0, sticky='nsew')
        self.shift_field = tk.Entry(self.input_frame, width=50)
        self.shift_field.grid(row=2, column=1, sticky='nsew')

        #create checkbox
        self.checkbox = tk.Checkbutton(self.input_frame, text="Random Shift", bg='#FFFFFF', variable=self.random)
        self.checkbox.grid(row=5, column=0, sticky='nsew')

        #create load button
        self.load_button = tk.Button(self.input_frame, text="Load", bg='#FFFFFF', command=self.load_button_clicked)
        self.load_button.grid(row=6, column=0, sticky='nsew')

        #create send button
        self.send_button = tk.Button(self.root, text="Send", command=self.send_button_clicked)
        self.send_button.grid(row=1, column=0, sticky='nsew')

        self.root.mainloop()

    def send_button_clicked(self):
        self.ip = str(self.ip_field.get())
        self.mac = self.mac_field.get()
        # self.shift = self.shift_field.get()
        self.port = self.port_field.get()
        self.message = self.message_field.get()
        # if self.random.get() == 1:
        #     self.shift = random.randint(0, 255)
        # else:
        #     self.shift = self.shift_field.get()
        #clear message field
        self.message_field.delete(0, 'end')

        self.send_packets(self.ip, self.mac, self.port, self.message)
    
    def load_button_clicked(self):
        #load text file
        self.file_path = tk.filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        self.file = open(self.file_path, 'r')
        self.message_field.delete(0, 'end')
        self.message_field.insert(0, self.file.read())
        self.file.close()

    def send_packets(self, ip, mac, port, message):
        #create packet
        # cyphertext = ceaser(message, int(shift))
        for car in message:
            if self.random.get() == 1:
                shift = random.randint(0, 255)
            else:
                shift = int(self.shift_field.get())
            cyphertext = ceaser(car, shift)
            # create UDP packet
            testchksum = int(hexlify(cyphertext.encode()), 16)
            #create an string the length of shift
            payload = ''.join(['\x00'] * int(shift))
            packet =  (Ether(dst=mac)/ IP(dst=ip) / UDP(sport=42069, dport=int(port), chksum=testchksum) / Raw(load=payload))
            #send packet
            sendp(packet, verbose=0)
            #wait a second
            time.sleep(.25)
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

if __name__ == '__main__':
    # dst = sys.argv[1]
    # dport = int(sys.argv[2])
    main()