import dpkt
import socket
import struct
from collections import defaultdict

class packet_structure:
    def __init__(self,src_ip,dest_ip,src_port,dest_port,ack,reset,fin,syn,psh,window_size,seq_num,ack_num,ts,buf_len,payload,is_valid,payload_data,mss=0):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.ack = ack
        self.reset = reset
        self.fin = fin
        self.syn = syn
        self.push = psh
        self.window_size = window_size
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.buf_len = buf_len
        self.is_valid = is_valid
        self.payload = payload
        self.payload_data = payload_data
        self.ts = ts
        self.mss = mss

    def get_src_ip(self):
        return self.src_ip
    def get_dest_ip(self):
        return self.dest_ip
    def get_src_port(self):
        return self.src_port
    def get_dest_port(self):
        return self.dest_port
    def get_is_ack(self):
        return self.ack
    def get_is_syn(self):
        return self.syn
    def get_is_fin(self):
        return self.fin
    def get_is_rst(self):
        return self.reset
    def get_ack_num(self):
        return self.ack_num
    def get_is_psh(self):
        return self.push
    def get_seq_num(self):
        return self.seq_num
    def get_window_size(self):
        return self.window_size
    def get_is_valid(self):
        return self.is_valid
    def get_ts(self):
        return self.ts
    def get_buf_size(self):
        return self.buf_len
    def get_payload(self):
        return self.payload
    def get_payload_data(self):
        return self.payload_data
    def get_mss(self):
        return self.mss

def getFlows(packets):
    flow = defaultdict(list)
    for pkt in packets:
        if pkt.get_is_valid():
            src_ip = pkt.get_src_ip()
            dst_ip = pkt.get_dest_ip()
            src_port = pkt.get_src_port()
            dst_port = pkt.get_dest_port()

            if pkt.get_is_syn() and not pkt.get_is_ack():
                flow[(src_ip,dst_ip,src_port,dst_port)].append(pkt)
            else:
                for fl in flow.keys():
                    if src_ip in fl and dst_ip in fl and src_port in fl and dst_port in fl:
                        flow[fl].append(pkt)
    return flow

def get_packets(pcap):
    packets = []
    for ts, buf in pcap:
        try:
            dest, src, protocol = struct.unpack('! 6s 6s H', buf[:14])
            data = buf[14:]
            if socket.htons(protocol) == 8:
                ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
                total_length = struct.unpack('! H', data[2:4])[0]
                data = data[(data[0] & 15) * 4:]
                src_ip = '.'.join(map(str, src))
                dest_ip = '.'.join(map(str, target))

                if proto == 6:
                    src_port = struct.unpack("! H", data[:2])[0]
                    dest_port = struct.unpack("! H", data[2:4])[0]
                    sequence = struct.unpack("! L", data[4:8])[0]
                    acknowledgment = struct.unpack("! L", data[8:12])[0]
                    flags = struct.unpack("! H", data[12:14])[0]
                    header_length = (data[12:13][0] & 0xF0) >> 4
                    payload_data = str(data[4*header_length:])
                    payload = total_length - 20 - 4*header_length
                    ack = (flags & 16) >> 4
                    rst = (flags & 4) >> 2
                    syn = (flags & 2) >> 1
                    psh = (flags & 8) >> 3
                    fin = flags & 1
                    window = struct.unpack("! H", data[14:16])[0]
                    if syn and src_ip == "172.24.22.110":
                        mss = struct.unpack("! H", data[22:24])[0]

                    pkt = packet_structure(src_ip,dest_ip,src_port,dest_port,ack,rst,fin,syn,psh,window,sequence,acknowledgment,ts,len(buf),payload,True,payload_data,mss)
                    packets.append(pkt)
        except Exception as e:
            pkt = packet_structure(None,None,None,None,None,None,None,None,None,None,None,None,ts,len(buf),None,None,False,None)
            packets.append(pkt)
    return packets

files = ['http_1080.pcap','tcp_1081.pcap','tcp_1082.pcap']
for id,fi in enumerate(files):
    f = open(fi,'rb')
    pcap = dpkt.pcap.Reader(f)
    packets = get_packets(pcap)
    if id == 0:
        print("Version: HTTP 1.0; pcap: http_1080.pcap")
    elif id == 1:
        print("Version: HTTP 1.1; pcap: tcp_1081.pcap")
    else:
        print("Version HTTP 2.0; pcap: tcp_1082.pcap")

    flows = getFlows(packets)

    if id == 0:
        for fl in flows:
            for i in range(len(flows[fl])):
                pkt = flows[fl][i]
                if 'GET' in pkt.get_payload_data():
                    print("Request : %s" %(pkt.get_payload_data()))
                    print("Src_IP: %s; Src_Port: %d; Destination_IP: %s; Destination_Port: %d" %(pkt.get_src_ip(), pkt.get_src_port(), pkt.get_dest_ip(), pkt.get_dest_port()))
                    print("Seq# : %d" %(pkt.get_seq_num()))
                    print("Ack# : %d" %(pkt.get_ack_num()))
                elif 'Connection' in pkt.get_payload_data():
                    print("Response : %s" %(pkt.get_payload_data()))
                    print("Src_IP: %s; Src_Port: %d; Destination_IP: %s; Destination_Port: %d" % (pkt.get_src_ip(), pkt.get_src_port(), pkt.get_dest_ip(), pkt.get_dest_port()))
                    print("Seq# : %d" %(pkt.get_seq_num()))
                    print("Ack# : %d" %(pkt.get_ack_num()))
                    print(" ")

    if id == 2 or id == 1:
        print("Number of TCP connections = %d" %(len(flows) - 1))
    else:
        print("Number of TCP connections = %d" % (len(flows)))
    print("Page load time: %f" %(packets[-1].get_ts() - packets[0].get_ts()))
    print("Packet Count = %d" %(len(packets)))
    pay_load_data = [len(pkt.get_payload_data()) for pkt in packets]
    print("Raw data size = %d bytes" %(sum(pay_load_data)))
    print(" ")





