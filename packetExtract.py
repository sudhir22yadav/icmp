from socket import inet_ntoa
from struct import pack, unpack
from binascii import hexlify

'''
Ethernet frame format:
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       Ethernet destination address (first 32 bits)            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Ethernet dest (last 16 bits)  |Ethernet source (first 16 bits)|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       Ethernet source address (last 32 bits)                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Type code              |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP Header Format:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IPv6 Header Format:
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Source Address                        +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination Address                      +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

'''


# extracting ethernet information
def eth_frame(data):
    '''
    Ethernet Frame, Please pass full data receieved by recvfrom function in sockets.
    It will pass the data minus the ethernet header, which can be used for further extractions
    '''
    mac_header = data[:14]  # MAC header is of 14 bytes 
    dst_mac, src_mac, eth_proto = unpack('!6s6sH', mac_header)  # extracting data using unpack() from struct
    # converting mac addresses in hex
    dst_mac = hexlify(dst_mac)
    src_mac = hexlify(src_mac)
    # checking for ip protocol used in the frame
    if eth_proto == 2048:
        proto = 'IPv4'
    elif eth_proto == 2054:
        proto = 'ARP'
    elif eth_proto == 34525:
        proto = 'IPv6'
    else:
        proto = 'UNKNOWN FOR NOW'
    # returning the values and data after removing the ethernet header
    return dst_mac, src_mac, proto, data[14:]


# extracting arp information
def arp(data):
    '''
    ARP - Adress Resolution Protocol, This method takes the data received via socket minus the ethernet header.
    if you are receiving data from from eth_frame(), you can use the same data. if not, then please pass data from 14th byte
    as we are assuming that ethernet header is no more then 14 bytes
    '''
    arp_packet = data[:28]  # ARP header is of 28 bytes after the ethernet header
    hw_type, proto_type, hw_addr_len, proto_len_addr, opcode, sender_mac, \
        sender_ip, target_mac, target_ip = unpack('!HHBBH6sI6sI', arp_packet) 
    # converting ipv4 addresses into ip readable form
    sender_ip = (inet_ntoa(pack('!L', sender_ip)))
    target_ip = (inet_ntoa(pack('!L', target_ip)))
    # converting mac addresses in hex
    sender_mac = hexlify(sender_mac)
    target_mac = hexlify(target_mac)
    # returning the values and data with arp header removed
    return hw_type, proto_type, hw_addr_len, proto_len_addr, opcode, sender_mac, \
        sender_ip, target_mac, target_ip, data[28:]


# extracting ipv6 data
def ipv6(packet):
    '''
    IP Version 6, This method takes the data received via socket minus the ethernet header.
    if you are receiving data from from eth_frame(), you can use the same data. if not, then please pass data from 14th byte
    as we are assuming that ethernet header is no more then 14 bytes
    '''
    ipv6_header = packet[:40]   # Considering this as fixed ipv6 header of 40 bytes
    ver_class_label, payload_length, next_header, hop_limit, src_addr, dst_addr = unpack(
        '!IHBB16s16s', ipv6_header)
    # converting ipv6 addresses in hex
    src_addr = hexlify(src_addr)
    dst_addr = hexlify(dst_addr)
    # using bit operation to find the version as first three bits are version field
    version = ver_class_label >> 28
    # returning values with data with ipv6 header removed
    return version, payload_length, next_header, hop_limit, src_addr, dst_addr, packet[40:]


# extracting ipv4 data
def ipv4(packet):
    '''    
    IP Version 4, This method takes the data received via socket minus the ethernet header.
    if you are receiving data from from eth_frame(), you can use the same data. if not, then please pass data from 14th byte
    as we are assuming that ethernet header is no more then 14 bytes
    '''
    ip_header = packet[:20] # we need first 40 bytes of ipv4 header
    ip_ver_len, ip_tos, ip_length, \
        ip_id, ip_flags, ip_ttl, ip_protocol, \
        ip_checksum, ip_src, ip_dst = unpack(
            "!BBHHHBBHII", ip_header)
    # using bit operations to find ip_version and ip header length
    ip_version = ip_ver_len >> 4
    ip_header_len = (ip_ver_len & 15) * 4
    # converting ipv4 addresses into ip readable form
    ip_src = (inet_ntoa(pack('!L', ip_src)))
    ip_dst = (inet_ntoa(pack('!L', ip_dst)))
    # returning values with data excluding full ipv4 header 
    return ip_version, ip_header_len, ip_ttl, ip_src, ip_dst, ip_protocol, packet[ip_header_len:]


# extracting icmp data
def icmp(packet):
    '''
    ICMP Header and Data extraction, it takes data as argument. Please the return value of data via ipv4() method.
    If you are not using ipv4(), please pass data from 34th byte. 
    '''
    icmp_header = packet[:8]
    icmp_type, icmp_code, icmp_check,\
        icmp_pid, icmp_seq = unpack("!BBHHH", icmp_header)
    return icmp_type, icmp_code, icmp_check, icmp_pid, icmp_seq, packet[8:]


#extracting icmpv6 data
def icmpv6(packet):
    '''
    ICMPv6 Header and Data extraction, it takes data as argument. Please the return value of data via ipv6() method.
    If you are not using ipv6(), please pass data from 54th byte.
    '''
    icmpv6_header = packet[:4]
    icmpv6_type, icmpv6_code, icmpv6_check = unpack('!BBH', icmpv6_header)
    return icmpv6_type, icmpv6_code, icmpv6_check, packet[4:]


# extracting tcp data
def tcp(data):
    '''
    TCP header and data extraction, pass data directly returned from ipv4() or ipv6 method, if you are not using any of this.
    please pass data from 34th Byte for IPv4 and 54th Byte for IPv6(keeping in mind that IPv6 has a fixed header) 
    '''
    tcp_header = data[:14]  # we need first 14 bytes of tcp header
    tcp_src_port, tcp_dst_port, seq, ack, off_flags = unpack(
        '!HHLLH', tcp_header)
    # using bit operations to find the below values
    offset = off_flags >> 12
    flag_urg = (off_flags >> 5) & 1
    flag_ack = (off_flags >> 4) & 1
    flag_psh = (off_flags >> 3) & 1
    flag_rst = (off_flags >> 2) & 1
    flag_syn = (off_flags >> 1) & 1
    flag_fin = off_flags & 1
    # returning the values and data excluding entire tcp header
    return tcp_src_port, tcp_dst_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# extracting udp data
def udp(data):
    '''
    UDP header and data extraction, pass data directly returned from ipv4() or ipv6 method, if you are not using any of this.
    please pass data from 34th Byte for IPv4 and 54th Byte for IPv6(keeping in mind that IPv6 has a fixed header) 
    '''
    udp_header = data[:8]
    udp_src_port, udp_dst_port, udp_len, udp_check = unpack(
        '!HHHH', udp_header)
    return udp_src_port, udp_dst_port, udp_len, udp_check, data[8:]


# extracting protocol under tcp or udp
def dns(data):
    '''
    DNS header and data extraction, data returned from udp() is passed in this. 
    You can pass data from 42nd Byte for IPv4 and 62nd Byte for IPv6(keeping in mind that IPv6 has a fixed header)
    '''
    dns_header = data[:12]
    identifier, flags_codes, ques_count, ans_rec_count, name_srv_count, additional_rec_count = unpack(
        '!HHHHHH', dns_header)
    qr_bit = flags_codes >> 15
    return identifier, qr_bit, ques_count, ans_rec_count, name_srv_count, additional_rec_count, data[12:]


#extracting IGMP
def igmp(data):
    '''
    IGMP header and data extraction, pass data directly returned from ipv4() or ipv6 method, if you
    are not using any of this. please pass data from 34th Byte for IPv4 and 54th Byte for IPv6(keeping in mind that IPv6 has a fixed header)
    '''
    igmp_header = data[:8]
    igmp_type, igmp_res_time, igmp_check, group_addr = unpack('!BBHL',igmp_header)
    group_addr = (inet_ntoa(pack('!L', group_addr)))
    return igmp_type, igmp_res_time, igmp_check, group_addr, data[8:]


#extracting DHCP 
def dhcp(data):
    '''
    DHCP header and data extraction, data returned from udp() or tcp() will be passed in this. 
    '''
    dhcp_header = data[:34]
    dhcp_opcode, hw_type, hw_addr_len, hop_count, transaction_id, num_seconds, flags, \
        client_ip_addr, your_ip_addr, srv_ip_addr, gw_ip_addr, client_hw_addr = unpack('!BBBBLHHLLLL6s', dhcp_header)
    # converting mac addresses in hex
    client_hw_addr = hexlify(client_hw_addr)
    return dhcp_opcode, hw_type, hw_addr_len, hop_count, transaction_id, num_seconds, flags, \
        client_ip_addr, your_ip_addr, srv_ip_addr, gw_ip_addr, client_hw_addr, data[28:]


#exctracting DHCPv6
def dhcpv6(data):
    '''
    DHCPv6 header and data extraction, pass data from udp() or tcp() will be passed in this
    '''
    message = data[:1]
    message = unpack('!B', message)
    return message, data[1:]

