import dpkt
import socket
import struct
import math
from collections import defaultdict

f = open('assignment2.pcap','rb')
#Read pcap file
pcap = dpkt.pcap.Reader(f)

class packet_structure:
    def __init__(self,src_ip,dest_ip,src_port,dest_port,ack,reset,fin,syn,psh,window_size,seq_num,ack_num,ts,buf_len,payload,is_valid,mss=0):
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
    def get_mss(self):
        return self.mss

def getIndex(lst,key):
    return lst.index(key)

def getThroughput(flow):
    print("******* Throughput *********")
    count = 0
    for fl in flow:
        size = flow[fl][0].get_buf_size()
        for i in range(1,len(flow[fl])):
            pkt = flow[fl][i]
            if pkt.get_dest_ip() == "128.208.2.198":
                size += pkt.get_buf_size()
            ts = pkt.get_ts()
        count += 1
        print("Flow %d: %d Bytes/sec" %(count,size/(ts - flow[fl][0].get_ts())))
    print(" ")

def PartB_A(flow):
    sender = "130.245.145.12"
    receiver = "128.208.2.198"
    for id,fl in enumerate(flow.keys()):
        seq = {}
        transaction = []
        for j in range(3,len(flow[fl])):
            if len(transaction) >= 2:
                break
            pkt = flow[fl][j]
            if sender == pkt.get_src_ip() and receiver == pkt.get_dest_ip():
               seq[pkt.get_seq_num()] = pkt
            else:
                if pkt.get_ack_num() in seq.keys():
                    res = getIndex(list(seq.keys()),pkt.get_ack_num())
                    seq_num = list(seq.keys())[res-1]
                    transaction.append((seq[seq_num],pkt))
        count = 0
        print("For srcPort = %s, i.e Flow = %d" %(fl[2],id+1))
        for pkta, pktb in transaction:
            count += 1
            print("Transaction %d" %(count))
            print("Seq#: %s, Ack#: %s, Window_Size = %s" %(pkta.get_seq_num(), pkta.get_ack_num(),int(pkta.get_window_size())*16384))
            print("Seq#: %s, Ack#: %s, Window_Size = %s" % (pktb.get_seq_num(), pktb.get_ack_num(), int(pktb.get_window_size()) * 16384))
            print(" ")

def getlossrate(flow):
    count = 0
    loss_rate = []
    print ("******* Loss Rate *********")
    for fl in flow:
        sender = "130.245.145.12"
        receiver = "128.208.2.198"
        seq = defaultdict(int)
        loss = 0
        for i in range(0,len(flow[fl])):
            pkt = flow[fl][i]
            if sender == pkt.get_src_ip() and receiver == pkt.get_dest_ip():
                seq[pkt.get_seq_num()] += 1
        for k in seq.keys():
            if seq[k] > 1:
                loss += seq[k]-1

        count += 1
        print("Flow %d: %f" %(count,loss/len(seq)))
        loss_rate.append(loss/len(seq))
    print(" ")
    return loss_rate

def getRtt(flow):
    sender = "130.245.145.12"
    receiver = "128.208.2.198"
    rtt_flow = []

    print("******* RTT *********")
    count = 0
    for fl in flow.keys():
        seq = defaultdict(float)
        ack = defaultdict(float)
        count += 1
        for pkt in flow[fl]:
            if pkt.get_is_valid():
                if str(pkt.get_src_ip()) == sender and str(pkt.get_dest_ip()) == receiver:
                    if seq[pkt.get_seq_num()] != 0:
                        continue
                    else:
                        seq[pkt.get_seq_num()] = pkt
                elif str(pkt.get_src_ip()) == receiver and str(pkt.get_dest_ip()) == sender:
                    if ack[pkt.get_ack_num()] != 0:
                        continue
                    else:
                        ack[pkt.get_ack_num()] = pkt

        trips, rtt, time = 0, 0.0, 0.0

        for seq_num in seq:
            pkt = seq[seq_num]
            if pkt.get_payload() == 0:
                if seq_num + 1 in ack:
                    trips += 1
                    time += ack[seq_num + 1].get_ts() - pkt.get_ts()
            else:
                if seq_num + pkt.get_payload() in ack:
                    trips += 1
                    time += ack[seq_num + pkt.get_payload()].get_ts() - pkt.get_ts()

        rtt = time / trips
        print("Flow %d: %f sec" % (count, rtt))
        rtt_flow.append(rtt)
    print(" ")
    return rtt_flow

def getFlows():
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

                payload = total_length - 20 - 4*header_length
                ack = (flags & 16) >> 4
                rst = (flags & 4) >> 2
                syn = (flags & 2) >> 1
                psh = (flags & 8) >> 3
                fin = flags & 1
                window = struct.unpack("! H", data[14:16])[0]
                if syn and src_ip == "130.245.145.12":
                    mss = struct.unpack("! H", data[22:24])[0]

                pkt = packet_structure(src_ip,dest_ip,src_port,dest_port,ack,rst,fin,syn,psh,window,sequence,acknowledgment,ts,len(buf),payload,True,mss)
                packets.append(pkt)
    except Exception as e:
        pkt = packet_structure(None,None,None,None,None,None,None,None,None,None,None,None,ts,len(buf),None,False)
        packets.append(pkt)

def getTheoreticalThroughput(flow,rtt,loss_rate):
    print("************ Theoretical Throughput ************")
    for id,fl in enumerate(flow.keys()):
        mss = 0
        for i in range(len(flow[fl])):
            if flow[fl][i].get_mss() != 0:
                mss = flow[fl][i].get_mss()
                break
        print("Flow %d: %f bytes/sec" %(id+1,(math.sqrt(1.5)*mss)/(math.sqrt(loss_rate[id])*rtt[id])))


flow = getFlows()
print("Total Number of flows = %d" %(len(flow)))
print(" ")
PartB_A(flow)
rtt = getRtt(flow)
loss_rate = getlossrate(flow)
getThroughput(flow)
getTheoreticalThroughput(flow,rtt,loss_rate)

