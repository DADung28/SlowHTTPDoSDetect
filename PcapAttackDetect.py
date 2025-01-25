import pylibpcap as lc
import struct
import socket
import time
import array
import socket
import sys
import csv
argv = sys.argv
#--------------Packet Dump---------------
def packet_dump(raw_data):
    size = len(raw_data)
    eth = ethernet_head(raw_data)
    dst_mac = eth[0]
    src_mac = eth[1]
    protocol_type = eth[2]
    eth_data = eth[3]
    #If connection is ipv4 then parse ipv4_head with ipv4_head() function
    if(eth[2] == 8):
        ipv4 = ipv4_head(eth_data)
        version = ipv4[0]
        header_length = ipv4[1]
        ttl = ipv4[2]
        protocol = ipv4[3]
        src_ip = ipv4[4]
        dst_ip = ipv4[5]
        ipv4_data = ipv4[6]
        #If packet is tcp packet
        if(protocol == 6):
            tcp = tcp_head(ipv4_data)
            src_port = tcp[0]
            dst_port = tcp[1]
            seq_num = tcp[2]
            ack_num = tcp[3]
            flag = flag_cal(tcp[4])
            window = tcp[5]
            tcp_data = tcp[6]
        else:
            src_port = None
            dst_port = None
            seq_num = None
            ack_num = None
            flag = []
            size = None
            window = None
            tcp_data = None
    else:
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        seq_num = None
        ack_num = None
        flag = []
        size = None
        window = None
        tcp_data = None
    return dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, flag, size, window, tcp_data
 #Parse ethernet header
def ethernet_head(raw_data):
    dst, src, protocol = struct.unpack('! 6s 6s H', raw_data[:14])
    dst = get_mac_addr(dst)
    src = get_mac_addr(src)
    protocol = socket.htons(protocol)
    data = raw_data[14:]
    return dst, src, protocol, data

#Make mac address readable
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#Parse IPV4 Header
def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    #
    ttl, protocol, src, dst = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    src = get_ip(src)
    dst = get_ip(dst)
    return version, header_length, ttl, protocol, src, dst, data

#Unpack TCP Packet
def tcp_head(raw_data):
    packet = struct.unpack("! 2H 2I 4H", raw_data[:20])
    src_port = int(packet[0])
    dst_port = int(packet[1])
    seq_num = packet[2]
    ack_num = packet[3]
    header_length = (packet[4] >> 12)* 4
    reserved = (packet[4] >> 6) & 0x003F
    flag = packet[4] & 0x003F
    window = packet[5]
    checkSum = packet[6]
    urgPntr = packet[7]
    data = raw_data[header_length:]
    return src_port, dst_port, seq_num, ack_num, flag, window, data
#Make IP readable
def get_ip(addr):
    return '.'.join(map(str, addr))

#format output line http
def format_output_line(prefix, string):
    size=80
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
#Caculate flag base on flag number
def flag_cal(flag_num):
    flags = {'urg' : (flag_num & 0x0020) >> 5, 'ack' : (flag_num & 0x0010) >> 4, 'psh' : (flag_num & 0x0008) >> 3,
                     'rst' : (flag_num & 0x0004) >> 2, 'syn' : (flag_num & 0x0002) >> 1, 'fin' : flag_num & 0x0001}
    available_flags = []
    for flag, num in flags.items():
        if num == 1:
            available_flags.append(flag)
    return available_flags

#-------------------Analyze-------------------
#-----------------------Slow Read-----------------------
def http_data_read(c, con,t):
    if c['flag'] == ['ack'] or c['flag'] == ['ack','psh']:
        http_data = c['data']
        con['server_idle_started'] = t
        if con['dst_port'] == 80:
            #If packet content HTTP/1.1 it will contain HTTP header
            if(http_data.find(b'HTTP')!=-1):
                #If con['http_count'] = 1, it mean packet include header from server is arrive
                con['server_http_count'] = 1
                #This mean this connection include http response
                con['http'] = True
            else:
                con['server_http_count'] += 1
            if(con['server_http_count'] == 1):
                #Header ending by \r\n\r\n
                header_end = http_data.find(b'\r\n\r\n')+4
                con['server_http_header'] = http_data[:header_end]
                con['server_http_body'] = http_data[header_end:]
                if con['server_http_header'].find(b'Content-Length') != -1:
                    content_length_farse = con['server_http_header'][con['server_http_header'].find(b'Content-Length'):]
                    #Content-length: 15800\r\n
                    try:
                        con['server_content_length'] = int(content_length_farse[content_length_farse.find(b':')+2:content_length_farse.find(b'\r')].decode('utf-8'))
                    except:
                        pass
                #Update body_length of arriving packet which is include http_header
                con['server_body_length'] = []
                con['server_body_length'].append(len(http_data[header_end:]))
            else:
                con['server_http_body'] += http_data
                con['server_body_length'].append(len(http_data))
        elif con['dst_port'] == 443:
            con['server_http_count'] += 1
            if con['server_http_count'] == 1:
                con['server_body_length'] = []
                con['server_body_length'].append(len(http_data)-255)
            else:
                con['server_body_length'].append(len(http_data))
    #Not update data when body length is 0
    if 0 in con['server_body_length']:
        con['server_body_length'].remove(0)
    return con

    #-----------------------Slow Head-----------------------
def http_data_head(c, con,t):
    if c['flag'] == ['ack'] or c['flag'] == ['ack','psh']:
        http_data = c['data']
        con['client_idle_started'] = t
        if con['dst_port'] == 80:
            #If packet content HTTP/1.1 it will contain HTTP header
            if(http_data.find(b'HTTP')!=-1):
                #If con['http_count'] = 1, it mean packet include header from server is arrive
                con['client_http_count'] = 1
                #This will count packet which include part of header (header not ended which \r\n\r\n)
                con['client_http_header_count'] = 1
                #This mean this connection include http request
                con['http'] = True
            else:
            #If packet is not have 'HTTP', it not include http request
                con['client_http_count'] += 1
            #Packet is the first http request and include first part of header
            if con['client_http_count'] == 1 and con['client_http_header_count'] == 1:
                #If header is ended
                if http_data.find(b'\r\n\r\n') != -1:
                    #Header ending by \r\n\r\n
                    header_end = http_data.find(b'\r\n\r\n')+4
                    con['client_header_end'] = True
                    con['client_http_header'] = http_data[:header_end]
                    con['client_http_body'] = http_data[header_end:]
                    if con['client_http_header'].find(b'Content-Length') != -1:
                        content_length_farse = con['client_http_header'][con['client_http_header'].find(b'Content-Length'):]
                        #Content-length: 15800\r\n
                        con['client_content_length'] = int(content_length_farse[content_length_farse.find(b':')+2:content_length_farse.find(b'\r')].decode('utf-8'))
                    con['client_body_length'] = []
                    con['client_body_length'].append(len(http_data[header_end:]))
                #If header not end, include count of header included packet counter
                else:
                    con['client_http_header_count'] += 1
                    con['client_http_header'] += http_data
            #If header is end and client start to delive request body
            elif con['client_http_count'] != 1 and con['client_http_header_count'] == 1:
                con['client_http_body'] += http_data
                con['client_body_length'].append(len(http_data))
            #If header is not end and client is trying to send packet include header
            elif con['client_http_count'] > 1 and con['client_http_header_count'] > 1:
                con['client_http_header_count'] += 1
                con['client_http_header'] += http_data
            #If there is no http request packet is receive
            else:
                con['client_http_header'] = ''
                con['client_http_body'] = ''
                con['client_body_length'] = []
        elif con['dst_port'] == 443:
            con['server_http_count'] += 1
            con['client_header_end'] = True
            if con['server_http_count'] == 1:
                con['body_length'] = []
                con['body_length'].append(len(http_data)-255)
            else:
                con['body_length'].append(len(http_data))
    return con

#Slow DoS Attack define
def is_slow_dos(con, established_time_threshold, idle_threshold):
    #Only with connection time > established_time_threshold
    if con['lived'] > established_time_threshold and con['http'] == True: 
        #Slow Read: Not finish read data from server and do nothing in idle threshold
        if con['server_idle'] >= idle_threshold and con['server_content_length'] > sum(con['server_body_length']) and con['server_body_end']==False:
            con['attack'] = 'SlowRead'
            return True
        #Slow Header: Not finish response header and do nothing in idle threshold
        elif con['client_idle']>=idle_threshold and con['client_header_end']==False :
            con['attack'] = 'SlowHeader'
            return True
        #SLow Body: Not finish request body and do nothing in idle threshold
        elif con['client_idle']>=idle_threshold and con['client_content_length'] > sum(con['client_body_length']) and con['client_body_end']==False:
            con['attack'] = 'SlowBody'
            return True
        else:
            return False
        
def main():
    csv_path = argv[2] + '/' + argv[3] + '_' + argv[4] + '.csv'
    f_csv = open(csv_path,'w')
    writer = csv.writer(f_csv)
    row = ['No.', 'id', 'Duration', 'Idle', 'Total Connection', 'Attack Connection']
    writer.writerow(row)
    c = {'id':'','src_mac':'', 'dst_mac':'','src_ip':'', 'dst_ip':'', 'src_port':'', 'dst_port':'', 'state':0, 'flag':[], 'size':0, 'window':0, 'data':''}
    
    #Rate time gap
    rate_gap = 1
    connecteds = {}
    attack = []
    pendings = {}
    interface = lc.get_first_iface()
    for plen, t, buf in lc.rpcap(argv[1]):
        c['src_mac'] = packet_dump(buf)[0]
        c['dst_mac'] = packet_dump(buf)[1]
        c['src_ip'] = packet_dump(buf)[2]
        c['dst_ip'] = packet_dump(buf)[3]
        c['src_port'] = packet_dump(buf)[4]
        c['dst_port'] = packet_dump(buf)[5]
        if(c['dst_port'] == 80):
                c['id'] = '{}({})->{}({})'.format(c['src_ip'],str(c['src_port']),c['dst_ip'],str(c['dst_port']))
        elif(c['src_port'] == 80):
            c['id'] = '{}({})->{}({})'.format(c['dst_ip'],str(c['dst_port']),c['src_ip'],str(c['src_port']))
        else:
            c['id'] = 'not_http'
        c['seq_num'] = packet_dump(buf)[6]
        c['ack_num'] = packet_dump(buf)[7]
        c['flag'] = packet_dump(buf)[8]
        c['size'] = packet_dump(buf)[9]
        c['window'] = packet_dump(buf)[10]
        c['data'] = packet_dump(buf)[11]
        #Add to connections when first arriving packet on port 80 have SYN flag
        if c['flag'] == ['syn'] and (c['dst_port'] == 80): 
                #Add connection to pending connection
            pendings.update({c['id']:{'src_ip':c['src_ip'], 'src_port':c['src_port'],
                            'dst_ip':c['dst_ip'], 'dst_port':c['dst_port'],
                            'ack' : 0, 'seq' : 0,
                            'forward_window':[], 'backward_window':[c['window']],
                            'started': t, 'idle_started': t, 'rate_start': t, 'time_data':{},
                            'server_idle_started': t, 'server_idle':0, 'client_idle_started': t, 'client_idle':0, 'client_header_idle_started': 0, 'client_header_idle':0,
                            'lived':0, 'idle':0, 'state':0, 'rate': 0, 'max_rate': 0,'size': c['size'],
                            'backward_size': 0, 'backward_rate': 0, 'backward_max_rate': 0,
                            'forward_size': 0, 'forward_rate': 0, 'forward_max_rate': 0,
                            'packet_count': 0, 'packet_rate': 0, 'packet_max_rate': 0,
                            'forward_packet': 0, 'backward_packet': 0, 'server_http_count': 0, 'client_http_count': 0, 'client_http_header_count': 0,
                            'server_http_header':b'','server_http_body':b'','server_content_length':0,'server_body_length':[],
                            'client_http_header':b'','client_http_body':b'','client_content_length':0,'client_body_length':[], 
                            'client_header_end': False, 'client_body_end': False,'server_body_end': False, 'http': False, 'attack':''}})
        #Only catch handshake and monitor if packet is TCP port 80 packet
        try:
            pending = pendings[c['id']]
            #3 Ways Handshake Define
            #Syn -> State = 0
            #Syn/Ack -> State = 1
            #Ack -> State = 2 -> ESTABLISHED
            #Fin | Rst -> State = 3 -> CLOSED
            if c['dst_ip'] == pending['src_ip'] and c['src_ip'] == pending['dst_ip'] and c['dst_port'] == pending['src_port'] and c['src_port'] == pending['dst_port'] and pending['state'] == 0 and c['flag'] == ['ack','syn']:
                #Change state after receive sys/ack packet
                pending['state']+=1
            elif c['dst_ip'] == pending['dst_ip'] and c['src_ip'] == pending['src_ip'] and c['dst_port'] == pending['dst_port'] and c['src_port'] == pending['src_port'] and pending['state'] == 1 and c['flag'] == ['ack']:
                #Change state after receive ack packet, establish connection
                pending['state']+=1
                #Add connection to connected and remove it from pending
                pending['packet_count']=3
                connecteds.update({c['id']:pending})
                pendings.pop(c['id'])
            #print('Pending:',len(pendings))
            #print('Connected:',len(connecteds))
            #Do this every while loop
            remove_list=[]
            for id, con in pendings.items():
                con['lived'] = t - con['started']
                #If connection does not complete hanshake in 3s delete it from pending
                if con['lived'] > 3:
                    #Send reset packet to connection
                    remove_list.append(id)
                    killed += 1
            for id in remove_list:
                pendings.pop(id)
        except:
            pass
        #-----------------Established Connection Analyze-------------------
        try:
            con = connecteds[c['id']]
            con['server_idle'] = t - con['server_idle_started']
            con['client_idle'] = t - con['client_idle_started']
            con_ip = [con['src_ip'],con['dst_ip']]
            con_port = [con['src_port'], con['dst_port']]
            if (('fin' in c['flag']) or ('rst' in c['flag'])) and (c['src_ip'] in con_ip) and (c['dst_ip'] in con_ip) and (c['src_port'] in con_port) and (c['dst_port'] in con_port) and con['state'] == 2:
                #Change state after receive fin | rst packet, close connection
                con['state']+=1
                #connecteds.pop(c['id'])
            
            #When packet in connection arrive from client:
            if c['src_ip'] == con['src_ip'] and c['src_port'] == con['src_port'] and c['dst_ip'] == con['dst_ip'] and c['dst_port'] == con['dst_port']:
            #Update ack and seq number for inject packet to connection
                len_data = len(c['data'])
                if(len_data == 0):
                    len_data = 1
                con['ack'] = c['seq_num'] + len_data
                con['seq'] = c['ack_num']
                con['backward_size'] += c['size']
                win = c['window']
                con['backward_window'].append(win)
                con['backward_packet'] += 1
                #Check if response is end or not
                #Request body must be bigger than 0
                #Total response body must be equal to Content-Length
                #If there is finished communation in connection it will define as finished body
                if con['client_content_length'] == sum(con['client_body_length']) and con['client_content_length'] != 0 and con['client_body_end'] == False:
                    con['client_body_end'] = True
                #----------------------Get client http data-------------------------------------
                #Parse http data function
                http_data_head(c,con,t)
            #When packet in connection arrive from server:
            elif c['src_ip'] == con['dst_ip'] and c['src_port'] == con['dst_port'] and c['dst_ip'] == con['src_ip'] and c['dst_port'] == con['src_port']:
                #con['ack'] = c['ack_num']
                #con['seq'] = c['seq_num'] + len(c['data'])
                con['forward_size'] += c['size']
                con['forward_window'].append(c['window'])
                con['forward_packet'] += 1
                #Check if response is end or not
                #Response body must be bigger than 0
                #Total response body must be equal to Content-Length
                #If there is finished communation in connection it will define as finished body
                if con['server_content_length'] == sum(con['server_body_length']) and con['server_content_length'] != 0 and con['server_body_end'] == False:
                    con['server_body_end'] = True
                    #print('{}({}) -> {}({}), lived: {}, server_idle: {}, client_idle: {}, server_content_length: {}, server_body_total_length: {}, client_content_length: {}, client_body_total_length: {}, header: {}'.format(con['src_ip'],con['src_port'],con['dst_ip'],con['dst_port'],round(con['lived']),round(con['server_idle']),round(con['client_idle']),con['server_content_length'],sum(con['server_body_length']),con['client_content_length'],sum(con['client_body_length']),con['client_header_end']))
                #----------------------Get server http data-------------------------------------
                #Parse http data function
                http_data_read(c,con,t)
                
            #When arriving packet is in connection
            if (c['src_ip'] in con_ip) and (c['dst_ip'] in con_ip) and (c['src_port'] in con_port) and (c['dst_port'] in con_port):
                con['idle'] = t - con['idle_started']
                #Reset idle time
                con['idle_started'] = t
                #Increase flow size when new packet arrive
                con['size'] += c['size']
                con['packet_count'] += 1
            
                
            #----------------------------------------------------------#

            #Connection rate each 1 second
            con['rate'] = con['size'] / rate_gap
            con['backward_rate'] = con['backward_size'] / rate_gap
            con['forward_rate'] = con['forward_size'] / rate_gap
            con['packet_rate'] = con['packet_count'] / rate_gap
            if con['rate'] > con['max_rate']:
                con['max_rate'] = con['rate']
            if con['packet_rate'] > con['packet_max_rate']:
                con['packet_max_rate'] = con['packet_rate']
            if con['backward_rate'] > con['backward_max_rate']:
                con['backward_max_rate'] = con['backward_rate']
            if con['forward_rate'] > con['forward_max_rate']:
                con['forward_max_rate'] = con['forward_rate']
            #Reset flow size every 1 second
            if t - con['rate_start'] > rate_gap:
                con['rate_start'] = t
                con['size'] = 0
                con['backward_size'] = 0
                con['forward_size'] = 0
                con['packet_count'] = 0
        except:
            pass
            
        for id in list(connecteds.keys()):
            con = connecteds[id]
            con['lived'] = t - con['started'] 
            con['idle'] = t - con['idle_started']
            if is_slow_dos(con, int(argv[3]), int(argv[4])):
                attack.append(con)
                connecteds.pop(id)
                pass
            
    for no, con in enumerate(attack):
        id = '{}({})->{}({})'.format(con['src_ip'],str(con['src_port']),con['dst_ip'],str(con['dst_port']))
        row = [no + 1, id, con['lived'], con['idle'], len(connecteds)+len(attack), len(attack)]
        writer.writerow(row)
        print('{}({}) -> {}({}), lived: {}, server_idle: {}, client_idle: {}, server_content_length: {}, server_body_total_length: {}, client_content_length: {}, client_body_total_length: {}, attack_type: {}'.format(con['src_ip'],con['src_port'],con['dst_ip'],con['dst_port'],round(con['lived']),round(con['server_idle']),round(con['client_idle']),con['server_content_length'],sum(con['server_body_length']),con['client_content_length'],sum(con['client_body_length']),con['attack']))
    print('Total http connect count: {}, Total attack count: {}, Accuracy: {}'.format(len(connecteds)+len(attack), len(attack), len(connecteds)/(len(connecteds)+len(attack))*100))
main()
