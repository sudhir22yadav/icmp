from socket import *
from packetExtract import *
from select import select
from datetime import datetime

try:
    while True:    
        icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        ready = select([icmp_sock], [], [], 3)
        if ready[0] == []:
            print('No data captured')
        else:
            data, addr = icmp_sock.recvfrom(65565)
            ip_version, ip_header_len, ip_ttl, ip_src, ip_dst, ip_protocol, ip_data = ipv4(data)
            icmp_type, icmp_code, icmp_check, icmp_pid,\
                icmp_seq, icmp_data = icmp(data[20:])
            if icmp_type == 8:
                with open('pingcheck.log', 'a') as log:
                    timestamp = str(datetime.now())
                    line = timestamp + '\nIP Address: ' + str(addr[0]) + ' is sending an ECHO Request\n'
                    log.writelines(line)

except Exception as e:
    print(e)
