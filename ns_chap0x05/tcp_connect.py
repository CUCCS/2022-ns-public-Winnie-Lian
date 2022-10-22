import logging
from symbol import del_stmt
from tkinter import N
logging.getLogger("scrapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

def tcp_connect(ip,port):
    pkt = sr1(IP(ip))/TCP(dprot=port,flags="")

    # Create SYN packet
    SYN = ip/TCP(sport=port,dport=80,flags="S",seq=42)
    SYN_ACK = sr1(SYN)

    # no response
    if SYN_ACK is None:
        logging.info("Port is filtered")
    
    # Send SYN and receive SYN,ACK
    elif SYN_ACK.getlayer(TCP).flags == 0x14 :
        # Create ACK packet
        ACK = ip/TCP(sport=SYN_ACK.dport,dport=80,flags="A",seq=SYN_ACK.ack,ack=SYN_ACK.seq+1)
        # send the ack packet
        send(ACK)
        logging.info("done！")

    
    


ip = input("please input target IP: ")
ip = IP(ip)

port = RandNum(1024,65535)
