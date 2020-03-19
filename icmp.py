import ipaddress
import select
import socket
import os
import struct
import time
'''
REFERENCES:
https://www.inf.ufrgs.br/~roesler/disciplinas/Labredes/LabCap5_NivelRede_PlanoControle/Cap5_Prog1_ICMPping.pdf
https://gist.github.com/pklaus/856268/b7194182270c816dee69438b54e42116ab31e53b
https://stackoverflow.com/questions/20905770/checksum-icmp-python-with-wireshark
https://stackoverflow.com/questions/3462784/check-if-a-string-matches-an-ip-address-pattern-in-python/48231784
https://stackoverflow.com/questions/3462784/check-if-a-string-matches-an-ip-address-pattern-in-python
'''

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIMEOUT = 11
PACKET_COUNT = 5
ID = os.getpid() & 0xFFFF


# checking for response
def receiveping(mySocket, timeout):

    left_time = timeout
    while True:  # Loop while waiting for packet
        start_time = time.time()
        ready = select.select([mySocket], [], [], left_time)
        select_time = (time.time() - start_time)
        if ready[0] == []:
            print("No Response Received!")
            return 0
        # Receiving the packet
        rec_packet, addr = mySocket.recvfrom(1024)
        receive_time = time.time()
        # Extracting IP Header information
        ip_header = rec_packet[:20]
        ip_version, ip_tos, ip_length, \
        ip_id, ip_flags, ip_ttl, ip_protocol, \
        ip_checksum, ip_src, ip_dest = struct.unpack("!BBHHHBBHII", ip_header)
        # Extracting ICMP Header information
        header = rec_packet[20:28]
        icmp_type, icmp_code, icmp_checksum, \
        icmp_pid, icmp_seq = struct.unpack("!BBHHH", header)
        delay = round((receive_time - start_time) * 1000)
        ip_src = (socket.inet_ntoa(struct.pack('!L', ip_src)))
        # checking if the type matches to icmp reply and the packet id matches
        if icmp_type == ICMP_ECHO_REPLY and icmp_pid == ID:
            data = len(rec_packet) - 28
            reply = str(data + 8)
            reply += ' bytes from ' + str(ip_src)
            reply += ' icmp_seq=' + str(icmp_seq)
            reply += ' ttl=' + str(ip_ttl)
            reply += ' time=' + str(delay) + 'ms'
            print(reply)
            #print("Reply from " + str(ip_src) + " bytes:" + str(data + 8) + \
            #      " time:" + str(delay) + "ms SeqNum:" + str(icmp_seq) + \
            #      " TTL:" + str(ip_ttl))
            return 1
        # Checking for timeout
        elif type == ICMP_TIMEOUT:
            print("Request timed out")
            return 0
        else:
            mySocket.close()

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


def gen_packet(mysocket, ip, seq):
    # Generating ICMP packet
    mycheck = 0
    header = struct.pack('!bbHHH', ICMP_ECHO_REQUEST, 0, mycheck, ID, seq)
    payload = bytes('Sudhir, this the data of the ICMP packet', 'utf-8')
    packet = header + payload
    mycheck = checksum(packet)
    mycheck = socket.htons(mycheck)
    # ICMP header with checksum
    header = struct.pack('!bbHHH', ICMP_ECHO_REQUEST, 0, mycheck, ID, seq)
    packet = header + payload
    # Sending the ICMP packet to the destination IP
    mysocket.sendto(packet, (ip, 1))

# Pinging the IP destination
def ping(dest, timeout=3):
    # creating a socket to send raw ip packets
    mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # Encoding destination ip into bytes
    ip = dest.encode('utf-8')
    print("Pinging to " + dest + " with the data:")
    received_packet = 0
    seq = 1
    while seq <= PACKET_COUNT:
        gen_packet(mysocket, ip, seq)
        received_packet += receiveping(mysocket, timeout)
        time.sleep(1)
        seq += 1
    success_rate = (received_packet / PACKET_COUNT) * 100
    report = '\nPing Statistics'
    report += '\nPing Packet sent: ' + str(PACKET_COUNT)
    report += ', Packet received: ' + str(received_packet)
    report += ' Success Rate: ' + str(success_rate) + '%'
    print(report)


# To check the entered IP is valid or not
def valid_ip(dest):
    # Function to check if the IP entered is valid or not
    try:
        ipaddress.IPv4Network(dest)
        return True
    except ValueError:
        return False

dest = input('Enter the IP you want to ping: ')

if valid_ip(dest) is True:
    ping(dest)
else:
    print("IP Address not Valid \n+++++++++++++++++++++++\nPlease run the script again")

