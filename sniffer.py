#! .env/bin/python3

from socket import *
from select import select
from struct import pack, unpack
from binascii import hexlify
from datetime import datetime
from packetExtract import *

def ip_protocols(ip_data, ip_protocol):
    if ip_protocol is IPPROTO_ICMP:
        icmp_type, icmp_code, icmp_check, icmp_pid,\
            icmp_seq, icmp_data = icmp(ip_data)
        icmp_data = hexlify(icmp_data)
        icmp_check = hex(icmp_check)
        icmp_msg = '\ticmp type: {}, icmp_code: {}, \
            icmp_check: {}, icmp_pid: {}, icmp_seq: {} \ndata: {} '
        print(icmp_msg.format(icmp_type, icmp_code, icmp_check,\
            icmp_pid, icmp_seq, icmp_data.decode('utf-8')))
    elif ip_protocol is IPPROTO_TCP:
        tcp_src_port, tcp_dst_port, seq, ack, flag_urg, flag_ack, \
            flag_psh, flag_rst, flag_syn, flag_fin, tcp_data = tcp(ip_data)
        tcp_data = hexlify(tcp_data)
        tcp_msg = 'TCP Segment:\t Source port: {}, Destination port: \
            {}, Sequence: {}, Acknowledgement: {},\n Flags:\t\t URG: {}, \
                ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}, \nData: {}'
        print(tcp_msg.format(tcp_src_port, tcp_dst_port, seq, ack,\
            flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, \
                tcp_data.decode('utf-8')))

    elif ip_protocol is IPPROTO_UDP:
        udp_src_port, udp_dst_port, udp_len, udp_check, \
            udp_data = udp(ip_data)
        udp_check = hex(udp_check)
        udp_msg = 'UDP Segment:\tSource port: {}, Destination port: \
            {}, Size: {}, Checksum: {}'
        print(udp_msg.format(udp_src_port, udp_dst_port, udp_len, udp_check))
        if udp_src_port == 53 or udp_dst_port == 53:
            identifier, qr_bit, ques_count, ans_rec_count, name_srv_count,\
                additional_rec_count, dns_data = dns(udp_data)
            dns_data = hexlify(dns_data)
            dns_msg = 'DNS Format: Identifier: {}, QR Bit: {}, Total Questions: \
                {}, Total Answers Records: {}, Total Authority Records: {}, Total \
                    Additional Records: {}, Data: {}'
            print(dns_msg.format(identifier, qr_bit, ques_count, ans_rec_count, \
                name_srv_count, additional_rec_count, dns_data.decode('utf-8')))
        else:
            udp_data = hexlify(udp_data)
            print('\nData: {}'.format(udp_data.decode('utf-8')))
    elif ip_protocol is IPPROTO_ICMPV6:
        icmpv6_type, icmpv6_code, icmpv6_check, icmpv6_data = icmpv6(ip_data)
        icmpv6_data = hexlify(icmpv6_data)
        icmpv6_check = hex(icmpv6_check)
        icmpv6_msg = 'ICMPv6 Data: Type: {}, Code: {}, Checksum: {}, Data: {}'
        print(icmpv6_msg.format(icmpv6_type, icmpv6_code, icmpv6_check, icmpv6_data.decode('utf-8')))
    elif ip_protocol is IPPROTO_IGMP:
        igmp_type, igmp_res_time, igmp_check, group_addr, igmp_data = igmp(ip_data)
        igmp_check = hex(igmp_check)
        igmp_data = hexlify(igmp_data)
        igmp_msg = 'IGMP Data: Type: {}, Response Time: {}, Checksum: {}, Group Address: {}, \nData: {}'
        print(igmp_msg.format(igmp_type, igmp_res_time, igmp_check, group_addr, igmp_data.decode('utf-8')))

def main(mysock):
    ready = select([mysock], [], [], 3)
    if ready[0] == []:
        print('No data captured')
    else:
        data, addr = mysock.recvfrom(65565)
        dst_mac, src_mac, eth_proto, data = eth_frame(data)
        print('\n' + str(datetime.now()))
        eth_msg = 'Destination MAC: {}, Source MAC: {}, Protocol: {}'\
            .format(dst_mac.decode('utf-8'), src_mac.decode('utf-8'), eth_proto)
        print(eth_msg)
        if eth_proto == 'IPv4':
            ip_version, ip_header_len, ip_ttl, ip_src, ip_dst, ip_protocol, ip_data = ipv4(data)
            ip_msg = 'IPv4: Version: {}, IP Header Length: {}, Time to live: {},'\
                .format(ip_version, ip_header_len, ip_ttl)
            ip_msg += ' Destination IP: {}, Source IP: {}, IP Protocol: {} '\
                .format(ip_src, ip_dst, ip_protocol)
            print(ip_msg)
            ip_protocols(ip_data, ip_protocol)
        elif eth_proto == 'ARP':
            hw_type, proto_type, hw_addr_len, proto_len_addr, opcode, \
                sender_mac, sender_ip, target_mac, target_ip, arp_data = arp(data)
            arp_data = hexlify(arp_data)
            arp_msg = 'ARP Format: Hardware type: {}, Protocol type: {}, Hardware Address Length: \
                {}, Protocol Length Address: {}, Opcode: {}, Sender HW Address: {}, Sender Protocol \
                    Address: {}, Target HW address: {}, Target Protocol Address: {}, ARP Data: {}'
            print(arp_msg.format(hw_type, proto_type, hw_addr_len, proto_len_addr,
                                 opcode, sender_mac, sender_ip, target_mac, target_ip, arp_data))
        elif eth_proto == 'IPv6':
            version, payload_length, next_header, hop_limit, src_addr, dst_addr, ip_data = ipv6(
                data)
            ipv6_msg = 'IPv6: Version: {}, Payload length: {}, Next Header: {}, TTL: {}, \
                Source Address: {}, Destination Address: {}'
            print(ipv6_msg.format(version, payload_length, next_header, hop_limit, \
                src_addr.decode('utf-8'), dst_addr.decode('utf-8')))
            ip_protocols(ip_data, next_header)


try:
    while True:
        mysock = socket(AF_PACKET, SOCK_RAW, ntohs(3))
        main(mysock)
except Exception as e:
    print(e)
