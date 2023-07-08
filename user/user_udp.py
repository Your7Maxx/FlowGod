from bcc import BPF
import socket
import ctypes as ct
import sys


sys.path.append('../utils/')
from tools import *

pid = None


def print_udp(cpu,data,size):
    class skbuffer_event(ct.Structure): # 兼容结构体
            _fields_ = [
                ("pid", ct.c_uint32),
                ("uid", ct.c_uint32),
                ("gid", ct.c_uint32),
                ("comm", ct.c_char * 64),
                ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32 * 3) - ct.sizeof(ct.c_char * 64)))
            ]
    skb = ct.cast(data, ct.POINTER(skbuffer_event)).contents
    packet_str = skb.raw[:]

    global pid

    if pid == 'all' or pid == skb.pid:
        if not is_dns_query(packet_str): # 暂时排除dns请求
            packet_bytearray = bytearray(packet_str)
            # calculate ip header length
            ip_header_length = packet_bytearray[ETH_HLEN]     # load Byte
            ip_header_length = ip_header_length & 0x0F        # mask bits 0..3
            ip_header_length = ip_header_length << 2          # shift to obtain length

            # calculate packet total length
            total_length = packet_bytearray[ETH_HLEN + 2]                 # load MSB
            total_length = total_length << 8                              # shift MSB
            total_length = total_length + packet_bytearray[ETH_HLEN + 3]  # add LSB

            # retrieve ip source/dest
            ip_src_str = packet_str[ETH_HLEN + 12: ETH_HLEN + 16]  # ip source offset 12..15
            ip_dst_str = packet_str[ETH_HLEN + 16:ETH_HLEN + 20]   # ip dest   offset 16..19

            ip_src = int.from_bytes(ip_src_str,"big")
            ip_dst = int.from_bytes(ip_dst_str,"big")

            port_src_str = packet_str[ETH_HLEN + ip_header_length:ETH_HLEN + ip_header_length + 2]
            port_dst_str = packet_str[ETH_HLEN + ip_header_length + 2:ETH_HLEN + ip_header_length + 4]

            port_src = str(int.from_bytes(port_src_str,"big"))
            port_dst = str(int.from_bytes(port_dst_str,"big"))

            print("[*] 原始数据报处理后提取的五元组信息：")
            print(int2ip(ip_src)+"[{}]".format(port_src)+"---->"+int2ip(ip_dst)+"[{}]".format(port_dst))
            print("-------------------------------------------------------------------------------")

            payload_header = ETH_HLEN + ip_header_length + UDP_HLEN
            print("[*] 原始数据报处理后提取的payload信息：")
            payload_str_bytes = packet_str[payload_header:(len(packet_bytearray))]

            print("-------------------------------------------------------------------------------")
            try:
                payload_str = bytearray(payload_str_bytes).decode('utf-8')
                print(payload_str)
                print("-------------------------------------------------------------------------------")
                print("PID\tUID\tCOMM\tCMD")
                with open(f'/proc/{skb.pid}/comm', 'r') as proc_comm:
                    proc_name = proc_comm.read().rstrip()
                with open(f'/proc/{skb.pid}/cmdline', 'r') as proc_cmd:
                    proc_cmd = proc_cmd.read().rstrip()
                    print("{}\t{}\t{}\t{}".format(skb.pid,skb.uid,proc_name,proc_cmd))
                    print("-------------------------------------------------------------------------------")
                    log_submit(int2ip(ip_src),port_src,int2ip(ip_dst),port_dst,"UDP",payload_str_bytes,skb.pid,skb.uid,proc_name,proc_cmd)
            except:
                proc_name = skb.comm.decode()


class Global():
    def __init__(self, pid, interface):
        self.pid = pid
        self.interface = interface


class UDP():

    def __init__(self, global_arg):

        self.bpf_kprobe_udp = BPF(src_file = "./udp/kprobe_udp.c")
        self.bpf_sock_udp = BPF(src_file = "./udp/udp.c")
        self.bpf_kprobe_udp.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
        function_udp_matching = self.bpf_sock_udp.load_func("udp_matching", BPF.SOCKET_FILTER)
        BPF.attach_raw_socket(function_udp_matching, global_arg.interface)
        socket_fd_udp = function_udp_matching.sock
        sock_udp = socket.fromfd(socket_fd_udp,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
        sock_udp.setblocking(True)
        self.bpf_sock_udp["events_udp"].open_perf_buffer(print_udp)

        print("[*] The UDP Hook is ready.")

    def udp_buffer_poll(self):
        while True:
            try:
                self.bpf_sock_udp.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()



def init(global_arg):
    libssl_path = global_arg.libssl_path
    interface = global_arg.interface
    global pid
    pid = global_arg.pid
    udp = UDP(global_arg)
    return udp

def run(udp):
    udp.udp_buffer_poll()


