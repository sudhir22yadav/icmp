#! .env/bin/python3

from socket import *
from select import select
from struct import pack, unpack
from binascii import hexlify
from datetime import datetime
from packetExtract import *

def ip_protocols(ip_data, ip_protocol):
    msg = ''
    if ip_protocol is IPPROTO_ICMP:
        icmp_type, icmp_code, icmp_check, icmp_pid,\
            icmp_seq, icmp_data = icmp(ip_data)
        icmp_data = hexlify(icmp_data)
        icmp_check = hex(icmp_check)
        icmp_msg = 'ICMP Segment:\ticmp type: {}, icmp_code: {}, icmp_check: {},'
        icmp_msg += ' icmp_pid: {}, icmp_seq: {} \ndata: {} '
        icmp_msg = icmp_msg.format(icmp_type, icmp_code, icmp_check,\
            icmp_pid, icmp_seq, icmp_data.decode('utf-8'))
        msg += icmp_msg
    elif ip_protocol is IPPROTO_TCP:
        tcp_src_port, tcp_dst_port, seq, ack, flag_urg, flag_ack, \
            flag_psh, flag_rst, flag_syn, flag_fin, tcp_data = tcp(ip_data)
        tcp_data = hexlify(tcp_data)
        tcp_msg = 'TCP Segment:\tSource port: {}, Destination port: {},'
        tcp_msg += ' Sequence: {}, Acknowledgement: {},\nFlags:\t\t '
        tcp_msg += 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}, \nData: {}'
        tcp_msg = tcp_msg.format(tcp_src_port, tcp_dst_port, seq, ack,\
            flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, \
                tcp_data.decode('utf-8'))
        msg += tcp_msg
    elif ip_protocol is IPPROTO_UDP:
        udp_src_port, udp_dst_port, udp_len, udp_check, \
            udp_data = udp(ip_data)
        udp_check = hex(udp_check)
        udp_msg = 'UDP Segment:\tSource port: {}, Destination port: {}, Size: {}, Checksum: {}'
        udp_msg = udp_msg.format(udp_src_port, udp_dst_port, udp_len, udp_check)
        if udp_src_port == 53 or udp_dst_port == 53:
            identifier, qr_bit, ques_count, ans_rec_count, name_srv_count,\
                additional_rec_count, dns_data = dns(udp_data)
            dns_data = hexlify(dns_data)
            dns_msg = 'DNS Format:\tIdentifier: {}, QR Bit: {}, Total Questions: {},'
            dns_msg += ' Total Answers Records: {}, Total Authority Records: {},'
            dns_msg += ' Total Additional Records: {}, Data: {}'
            dns_msg = dns_msg.format(identifier, qr_bit, ques_count, ans_rec_count, \
                name_srv_count, additional_rec_count, dns_data.decode('utf-8'))
            msg += dns_msg
        else:
            udp_data = hexlify(udp_data)
            udp_data = '\nData: {}'.format(udp_data.decode('utf-8'))
            udp_msg += udp_data
            msg += udp_msg
    elif ip_protocol is IPPROTO_ICMPV6:
        icmpv6_type, icmpv6_code, icmpv6_check, icmpv6_data = icmpv6(ip_data)
        icmpv6_data = hexlify(icmpv6_data)
        icmpv6_check = hex(icmpv6_check)
        icmpv6_msg = 'ICMPv6 Data:\tType: {}, Code: {}, Checksum: {}, Data: {}'
        icmpv6_msg =icmpv6_msg.format(icmpv6_type, icmpv6_code, icmpv6_check, icmpv6_data.decode('utf-8'))
        msg += icmpv6_msg
    elif ip_protocol is IPPROTO_IGMP:
        igmp_type, igmp_res_time, igmp_check, group_addr, igmp_data = igmp(ip_data)
        igmp_check = hex(igmp_check)
        igmp_data = hexlify(igmp_data)
        igmp_msg = 'IGMP Data:\tType: {}, Response Time: {}, Checksum: {}, Group Address: {}, \nData: {}'
        igmp_msg = igmp_msg.format(igmp_type, igmp_res_time, igmp_check, group_addr, igmp_data.decode('utf-8'))
        msg += igmp_msg
    return msg


def main(mysock):
    ready = select([mysock], [], [], 3)
    if ready[0] == []:
        msg = 'No data captured'
        print(msg)
    else:
        data, addr = mysock.recvfrom(65565)
        eth_msg = '\n'+'-'*27
        eth_msg += '\n' + str(datetime.now()) + '|\n'
        dst_mac, src_mac, eth_proto, data = eth_frame(data)
        eth_msg += '-' * 101
        eth_msg += '\nDestination MAC Address: {} | Source MAC Address: {} | Protocol: {} |\n'\
            .format(dst_mac, src_mac, eth_proto)
        eth_msg += '-' * 101

        if eth_proto == 'IPv4':
            ip_version, ip_header_len, ip_ttl, ip_src, ip_dst, ip_protocol, ip_data = ipv4(data)
            ip_msg = '\nIPv4 Packet:\tVersion: {}, IP Header Length: {}, Time to live: {}'\
                .format(ip_version, ip_header_len, ip_ttl)
            ip_msg += ' Destination IP: {}, Source IP: {}, IP Protocol: {} '\
                .format (ip_dst, ip_src, ip_protocol)
            msg = eth_msg + ip_msg + ip_protocols(ip_data, ip_protocol)
            
        elif eth_proto == 'ARP':
            hw_type, proto_type, hw_addr_len, proto_len_addr, opcode, \
                sender_mac, sender_ip, target_mac, target_ip, arp_data = arp(data)
            arp_data = hexlify(arp_data)
            arp_msg = '\nARP Format:\tHardware type: {}, Protocol type: {}, Hardware Address Length: {},'
            arp_msg += ' Protocol Length Address: {}, Opcode: {}, Sender HW Address: {},'
            arp_msg += ' Sender Protocol Address: {}, Target HW address: {}, Target Protocol Address: {},\n'
            arp_msg += ' ARP Data: {}'
            arp_msg = arp_msg.format(hw_type, proto_type, hw_addr_len, proto_len_addr,
                                 opcode, sender_mac, sender_ip, target_mac, target_ip, arp_data)
            msg = eth_msg + arp_msg
        
        elif eth_proto == 'IPv6':
            version, payload_length, next_header, hop_limit, src_addr, dst_addr, ip_data = ipv6(
                data)
            ipv6_msg = '\nIPv6 Packet:\tVersion: {}, Payload length: {}, Next Header: {}, TTL: {}, '
            ipv6_msg += 'Source Address: {}, Destination Address: {}'
            ipv6_msg = ipv6_msg.format(version, payload_length, next_header, hop_limit, \
                src_addr, dst_addr)
            msg = eth_msg + ipv6_msg + ip_protocols(ip_data, next_header)
    print(msg)
            

try:
    while True:
        mysock = socket(AF_PACKET, SOCK_RAW, ntohs(3))
        main(mysock)
except Exception as e:
    print(e)
except KeyboardInterrupt:
    print('\n')
