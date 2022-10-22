
import logging

logging.basicConfig(level=logging.INFO)


from scapy.all import *

def tcp_connect(ip,port,dport):

    # Create SYN packet
    SYN = ip/TCP(sport=port,dport=dport,flags="S",seq=42)
    SYN_ACK = sr1(SYN,timeout=5)
    logging.info("Send SYN!")

    # no response
    if SYN_ACK is None:
        logging.info("Port %d is filtered" % SYN.dport) 
    
    
    # Send SYN and receive SYN,ACK
    elif SYN_ACK.getlayer(TCP).flags == 'SA':
        logging.info("Port %d is OPEN!" % SYN.dport)
        logging.info("The answer flag is %s" % SYN_ACK.getlayer(TCP).flags)
        # Create ACK packet
        ACK = ip/TCP(sport=SYN_ACK.dport,dport=22,flags="A",seq=SYN_ACK.ack,ack=SYN_ACK.seq+1)
        # send the ack packet
        send(ACK)
        logging.info("Send ACK!")
        logging.info("TCP 3 Handshakes done！")


    elif SYN_ACK.getlayer(TCP).flags == 'RA' :
        logging.info("Port %d is CLOSE!" % SYN.dport)
        logging.info("The answer flag is %s" % SYN_ACK.getlayer(TCP).flags)

    else:
        logging.error("There must be something wrong!")
            

def tcp_stealth(ip,port,dport):
        # Create SYN packet
    SYN = ip/TCP(sport=port,dport=dport,flags="S",seq=42)
    SYN_ACK = sr1(SYN,timeout=5)
    logging.info("Send SYN!")

    # no response
    if SYN_ACK is None:
        logging.info("Port %d is filtered" % SYN.dport) 
    
    
    # Send SYN and receive SYN,ACK
    elif SYN_ACK.getlayer(TCP).flags == 'SA':
        logging.info("Port %d is OPEN!" % SYN.dport)
        logging.info("The answer flag is %s" % SYN_ACK.getlayer(TCP).flags)
        # Create ACK packet
        RST = ip/TCP(sport=SYN_ACK.dport,dport=22,flags="R",seq=SYN_ACK.ack,ack=SYN_ACK.seq+1)
        # send the ack packet
        send(RST)
        logging.info("Send RST!")


    elif SYN_ACK.getlayer(TCP).flags == 'RA' :
        logging.info("Port %d is CLOSE!" % SYN.dport)
        logging.info("The answer flag is %s" % SYN_ACK.getlayer(TCP).flags)

    else:
        logging.error("There must be something wrong!")


def tcp_fin(ip,port,dport):
    # Create SYN packet
    FIN = ip/TCP(sport=port,dport=dport,flags="F",seq=42)
    FIN_ACK = sr1(FIN,timeout=10)
    logging.info("Send FIN!")

    # no response
    if FIN_ACK is None:
        logging.info("Port %d is filtered or OPEN" % FIN.dport) 
    
    
    # Send SYN and receive SYN,ACK
    elif FIN_ACK.getlayer(TCP).flags == 'RA':
        logging.info("Port %d is CLOSE!" % FIN.dport)
        logging.info("The answer flag is %s" % FIN_ACK.getlayer(TCP).flags)

    else:
        logging.error("There must be something wrong!")


def tcp_Xmas(ip,port,dport):
     # Create packet
    FUP = ip/TCP(sport=port,dport=dport,flags="FUP",seq=42)
    FUP_ACK = sr1(FUP,timeout=10)
    logging.info("Send a packet with flag FIN URGE PUSH!")

    # no response
    if FUP_ACK is None:
        logging.info("Port %d is filtered or OPEN" % FUP.dport) 


    elif FUP_ACK.getlayer(TCP).flags == 'RA' :
        logging.info("Port %d is CLOSE!" % FUP.dport)
        logging.info("The answer flag is %s" % FUP_ACK.getlayer(TCP).flags)

    else:
        logging.error("There must be something wrong!")


def tcp_null(ip,port,dport):
      # Create packet
    FUP = ip/TCP(sport=port,dport=dport,flags="",seq=42)
    FUP_ACK = sr1(FUP,timeout=10)
    logging.info("Send a packet with no flag!")

    # no response
    if FUP_ACK is None:
        logging.info("Port %d is filtered or OPEN" % FUP.dport) 


    elif FUP_ACK.getlayer(TCP).flags == 'RA' :
        logging.info("Port %d is CLOSE!" % FUP.dport)
        logging.info("The answer flag is %s" % FUP_ACK.getlayer(TCP).flags)

    else:
        logging.error("There must be something wrong!")


def UDP_scan(ip,port,dport):
     # Create packet
    udp = ip/UDP(sport=port,dport=dport)
    udp_ACK = sr1(udp,timeout=10)
    logging.info("Send a packet with no flag!")

    # no response
    if udp_ACK is None:
        logging.info("Port %d is filtered or OPEN" % udp.dport) 


    elif udp_ACK.getlayer(ICMP):
        udp_ACK.summary()
        logging.info("Port %d is CLOSE!" % udp.dport)
        logging.info("The answer code is %s" % udp_ACK.getlayer(ICMP).code)

    else:
        logging.error("There must be something wrong!")

def pre():
    ip = input("please input target IP: ")
    if ip == "":
        print("default ip :172.16.222.1")
        ip = "172.16.222.1"
    # print(ip)
    ip = IP(dst=ip)
    port = RandNum(1024,65535)
    dport = int(input("please input target port: "))
    print("\n******function called******")
    return ip,port,dport



h = int(input("====help====\n1-tcp_connet\n2-tcp_stealth\n3-tcp_fin\n4-tcpXmas\n5-tcp_null\n6-udp\n7-exit\n"))
while(h != 7):
    ip,port,dport = pre()
    if h == 1:
        tcp_connect(ip,port,dport)
    if h==2:
        tcp_stealth(ip,port,dport)
    if h==3:
        tcp_fin(ip,port,dport)
    if h==4:
        tcp_Xmas(ip,port,dport)
    if h==5:
        tcp_null(ip,port,dport)
    if h==6:
        UDP_scan(ip,port,dport)
    if h==7:
        break
    h = int(input("\n\n====help====\n1-tcp_connet\n2-tcp_stealth\n3-tcp_fin\n4-tcpXmas\n5-tcp_null\n6-udp\n7-exit\n"))


# ip = input("please input target IP: ")
# # print(ip)
# ip = IP(dst=ip)
# port = RandNum(1024,65535)
# dport = int(input("please input target port: "))
# # tcp_connect(ip,port,dport)

# # tcp_stealth(ip,port,dport)

# # tcp_fin(ip,port,dport)

# # tcp_Xmas(ip,port,dport)

# # tcp_null(ip,port,dport)

# UDP_scan(ip,port,dport)