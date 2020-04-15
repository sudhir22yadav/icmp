#! .env/bin/python3

import ipaddress
import socket
import struct
import time
import random
import select
import argparse
import os

# IP Global Variables
IP_VER_IHL = 69
IP_TOS = 0
IP_TOTAL_LEN = 0        # Not affecting anything in the IP Packet
IP_IDENTITY = 54321
IP_FLAG_FRAG = 0
IP_PROTO_UDP = 17

# ICMP Global Variables
PACKET_COUNT = 3
MAX_HOPS = 30
SECONDS = random.uniform(0.50, 1.0)
ICMP_ECHO_REQUEST = 8
IP_PROTO_ICMP = 1
ID = os.getpid() & 0xFFFF

# Carry Around needed for checksum function
def carry_around_add(a, b):
    f = 1 << 16
    c = a + b
    return c if c < f else c + 1 - f

# Checksum function for ICMP header checksum
def checksum(packet):
    if len(packet) % 2:
        packet += b'\x00'
    s = 0
    for i in range(0, len(packet), 2):
        w = (packet[i]) + ((packet[i + 1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff


def receive(ip_dest):
    sck = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    ready = select.select([sck], [], [], 5)
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
                            IP_IDENTITY, IP_FLAG_FRAG, ip_ttl, IP_PROTO_ICMP, ip_check)
    ip_header += ip_src + ip_dest

    # Generating ICMP packet
    mycheck = 0
    header = struct.pack('!bbHHH', ICMP_ECHO_REQUEST, 0, mycheck, ID, ip_ttl)
    payload = bytes('this the data of the ICMP packet', 'utf-8')
    packet = header + payload
    mycheck = checksum(packet)
    mycheck = socket.htons(mycheck)
    # ICMP header with checksum
    header = struct.pack('!bbHHH', ICMP_ECHO_REQUEST, 0, mycheck, ID, ip_ttl)
    packet = header + payload
    # Combined Header
    full_packet = ip_header + packet
    return full_packet

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

            time.sleep(SECONDS)

        if check:
            if ip_dest == hop_ip:
                print(ip_ttl, '.', hop_ip, delays[0], delays[1], delays[2])
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
    parser.add_argument('ip', help='Provide ip address or domain to trace')
    args = parser.parse_args()

    ip_dest = socket.gethostbyname(args.ip)
    if valid_ip(ip_dest):
        traceroute(ip_dest)
    else:
        print('IP Address not Valid ')
except Exception as e:
    print(e)

