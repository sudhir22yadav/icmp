#! .env/bin/python3

import ipaddress
import socket
import struct
import time
import random
import select
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
MAX_HOPS = 3
SECONDS = random.uniform(0.50, 1.0)


def receive(ip_dest):
    sck = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    ready = select.select([sck], [], [], 3)
    if ready[0] == []:
        return '0', False
    else:
        rec_packet, addr = sck.recvfrom(1024)
        if addr[0] == ip_dest:
            sck.close()
            return addr[0], True
        else:
            sck.close()
            return addr[0], True


def gen_header(ip_dest, ip_ttl):
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
    while hop_ip != ip_dest and ip_ttl <= MAX_HOPS:
        delays = []
        for i in range(PACKET_COUNT):
            start_time = time.time()
            header = gen_header(ip_dest, ip_ttl)
            mysocket.sendto(header, (ip_dest, 0))
            hop_ip, check = receive(ip_dest)
            recv_time = time.time()
            if check:
                delays.append(
                    str(round((recv_time - start_time)*1000)) + ' ms')
            elif check is False:
                delays.append('*')
            
            #time.sleep(SECONDS)
        
        if check: 
            if ip_dest == hop_ip:
                print(ip_ttl, '.', hop_ip, delays[0], delays[1], delays[2])
                print('Traceroute finished after', ip_ttl, ' Hops')
                mysocket.close()
            elif ip_ttl >= MAX_HOPS:
                print(ip_ttl, '.', hop_ip, delays[0], delays[1], delays[2])
                mysocket.close()
                print('Maximum Hops traversed')
                break
            else:
                print(ip_ttl, '.', hop_ip, delays[0], delays[1], delays[2])
        elif check is False:
            if ip_ttl < MAX_HOPS:
                print(ip_ttl, '.', delays[0], delays[1], delays[2])
            elif ip_ttl >= MAX_HOPS:
                print(ip_ttl, '.', delays[0], delays[1], delays[2])
                mysocket.close()
                print('Maximum Hops traversed, No Response Received')
                break
        ip_ttl += 1

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


