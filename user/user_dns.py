from bcc import BPF
import socket
import ctypes as ct
import sys


sys.path.append('../utils/')
from tools import *

pid = None


def print_dns(cpu, data, size):
    import ctypes as ct
    class SkbEvent (ct.Structure):
        _fields_ = [
            ("pid", ct.c_uint32),
            ("uid", ct.c_uint32),
            ("gid", ct.c_uint32),
            ("comm", ct.c_char * 64),
            ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32 * 3) - ct.sizeof(ct.c_char * 64)))
        ]
    # We get our 'port_val' structure and also the packet itself in the 'raw' field:
    skb = ct.cast(data, ct.POINTER(SkbEvent)).contents
    packet_str = skb.raw[:]
    packet_bytearray = bytearray(packet_str)

    ip_header_length = packet_bytearray[ETH_HLEN]     # load Byte
    ip_header_length = ip_header_length & 0x0F        # mask bits 0..3
    ip_header_length = ip_header_length << 2          # shift to obtain length

    # calculate packet total length
    total_length = packet_bytearray[ETH_HLEN + 2]                 # load MSB
    total_length = total_length << 8                              # shift MSB
    total_length = total_length + packet_bytearray[ETH_HLEN + 3]  # ad+d LSB

    # retrieve ip source/dest
    ip_src_str = packet_str[ETH_HLEN + 12: ETH_HLEN + 16]  # ip source offset 12..15
    ip_dst_str = packet_str[ETH_HLEN + 16:ETH_HLEN + 20]   # ip dest   offset 16..19
    ip_src = int.from_bytes(ip_src_str,"big")
    ip_dst = int.from_bytes(ip_dst_str,"big")
    port_src_str = packet_str[ETH_HLEN + ip_header_length:ETH_HLEN + ip_header_length + 2]
    port_dst_str = packet_str[ETH_HLEN + ip_header_length + 2:ETH_HLEN + ip_header_length + 4]
    port_src = int.from_bytes(port_src_str,"big")
    port_dst = int.from_bytes(port_dst_str,"big")



    udp_header_len = 14 + ip_header_length
    udp_packet = bytes(skb.raw[udp_header_len:])
    dns_packet = udp_packet[8:]

    DNS_Q_TYPE = {1: "A", 28: "AAAA"}

    dns_data = dnslib.DNSRecord.parse(dns_packet)

    #print(dns_data)
    if dns_data.header.qr == 0:
        for q in dns_data.questions:
            print("[DNS] 原始数据报处理后提取的五元组信息：")
            print(int2ip(ip_src)+"[{}]".format(port_src)+"---->"+int2ip(ip_dst)+"[{}]".format(port_dst))
            print("-------------------------------------------------------------------------------")
            print("[DNS] 原始数据报处理后提取的DNS请求信息：")
            print("-------------------------------------------------------------------------------")
            print("DNS QUESTION SECTION: ")
            print(str(q.qname) + "\t" + "IN\t" + DNS_Q_TYPE[q.qtype])
            print("-------------------------------------------------------------------------------")

    try:
        with open(f'/proc/{skb.pid}/comm', 'r') as proc_comm:
            proc_name = proc_comm.read().rstrip()
        with open(f'/proc/{skb.pid}/cmdline', 'r') as proc_cmd:
            proc_cmd = proc_cmd.read().rstrip()
    except:
        proc_name = skb.comm.decode()
        proc_cmd = "NULL"

    print("PID\tUID\tCOMM\tCMD")
    print("{}\t{}\t{}\t{}".format(skb.pid,skb.uid,proc_name,proc_cmd))
    print("-------------------------------------------------------------------------------")


class Global():
    def __init__(self, pid, interface):
        self.pid = pid
        self.interface = interface


class DNS():

    def __init__(self, global_arg):

        self.bpf_kprobe_dns = BPF(src_file = "./dns/dns_udp_pro.c")
        self.bpf_sock_dns = BPF(src_file = "./dns/dns_socket_pro.c")
        self.bpf_kprobe_dns.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
        function_dns_matching = self.bpf_sock_dns.load_func("dns_matching", BPF.SOCKET_FILTER)
        BPF.attach_raw_socket(function_dns_matching, global_arg.interface)
        socket_fd_dns = function_dns_matching.sock
        sock_dns = socket.fromfd(socket_fd_dns,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
        sock_dns.setblocking(True)
        self.bpf_sock_dns["events_dns"].open_perf_buffer(print_dns)

        print("[*] The DNS Hook is ready.")

    def dns_buffer_poll(self):
        while True:
            try:
                self.bpf_sock_dns.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()



def init(global_arg):
    libssl_path = global_arg.libssl_path
    interface = global_arg.interface
    global pid
    pid = global_arg.pid
    dns = DNS(global_arg)
    return dns

def run(dns):
    dns.dns_buffer_poll()


