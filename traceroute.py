#! .env/bin/python3

import ipaddress
import socket
import struct
import time
import random
import argparse

# IP Global Variables
IP_VER_IHL = 69
IP_TOS = 0
IP_TOTAL_LEN = 0        # Not affecting anything in the IP Packet
IP_IDENTITY = 54321
IP_FLAG_FRAG = 0
IP_PROTO_UDP = 17

# UDP Global Variables
UDP_SRC_PORT = 44354
UDP_DEST_PORT = random.randint(33434, 33534)
UDP_LEN = 8
PACKET_COUNT = 3
SECONDS = random.uniform(0.50, 1.0)


def receive(ip_dest):
    sck = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    rec_packet, addr = sck.recvfrom(1024)
    if addr[0] == ip_dest:
        sck.close()
        return addr[0], True
    else:
        sck.close()
        return addr[0], False


def gen_header(ip_dest, ip_ttl, mysocket):
    # IP Header
    ip_check = 0
    ip_src = '0.0.0.0'
    ip_src = socket.inet_aton(ip_src)
    ip_dest = socket.inet_aton(ip_dest)
    ip_header = struct.pack('!BBHHHBBH', IP_VER_IHL, IP_TOS, IP_TOTAL_LEN,
                            IP_IDENTITY, IP_FLAG_FRAG, ip_ttl, IP_PROTO_UDP, ip_check)
    ip_header += ip_src + ip_dest
    
    # UDP Header
    udp_check = 0
    udp_header = struct.pack('!HHHH', UDP_SRC_PORT,
                             UDP_DEST_PORT, UDP_LEN, udp_check)
    udp_payload = bytes('this is udp payload', 'utf-8')
    udp_header += udp_payload

    # Combined Header
    header = ip_header + udp_header
    return header


def traceroute(ip_dest):
    ip_ttl = 1
    hop_ip = ''
    while hop_ip != ip_dest :
        delays = []
        for i in range(PACKET_COUNT):
            start_time = time.time()
            header = gen_header(ip_dest, ip_ttl, mysocket)
            mysocket.sendto(header, (ip_dest, 0))
            hop_ip, check = receive(ip_dest)
            recv_time = time.time()
            delays.append( str(round((recv_time - start_time)*1000)) + ' ms')
            time.sleep(SECONDS)
        print(ip_ttl, '.', hop_ip, delays[0], delays[1], delays[2])
        ip_ttl += 1

        if check and ip_dest == hop_ip:
            print('Traceroute finished after', ip_ttl, ' Hops')
            mysocket.close()


# To check the entered IP is valid or not
def valid_ip(dest):
    # Function to check if the IP entered is valid or not
    try:
        ipaddress.IPv4Network(dest)
        return True
    except ValueError:
        return False


try:
    mysocket = socket.socket(
        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    mysocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    parser = argparse.ArgumentParser()
    parser.add_argument('ip', help= 'Provide ip address or domain to trace')
    args = parser.parse_args()

    ip_dest = socket.gethostbyname(args.ip)
    if valid_ip(ip_dest):
        traceroute(ip_dest)
    else:
        print('IP Address not Valid ')
except Exception as e:
    print(e)


