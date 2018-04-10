from scapy.all import *
import sys
class sniffer():
    def dhcp_monitor(self,pkt):
        if pkt[DHCP]:
            print str(pkt[IP].dst)+" dst"

        elif pkt[DHCP].options[0][1]==6:
            print "NAK received"

    def listen(self):
        sniff(filter="udp and (port 67 or port 68)",prn=self.dhcp_monitor,store=0)

    def start(self):
        # start packet listening thread
        thread = Thread(target=self.listen)
        thread.start()
        print "Starting DHCP Monitoring..."

if __name__=="__main__":
    sniffer = sniffer()
    sniffer.start()

    
