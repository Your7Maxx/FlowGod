from bcc import BPF
import socket
import ctypes as ct
import sys

sys.path.append('../utils/')
from tools import *

pid = None
http_sessions = None
http_packet_count = 0
http_packet_dictionary = {}

def print_http(cpu,data,size):
    class skbuffer_event(ct.Structure): # 兼容
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
    #print(pid,type(pid),skb.pid,type(skb.pid))
    if pid == 'all' or pid == str(skb.pid):
        if not is_dns_query(packet_str): # 暂时排除dns请求
            packet_bytearray = bytearray(packet_str)

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
            port_src = int.from_bytes(port_src_str,"big")
            port_dst = int.from_bytes(port_dst_str,"big")

            tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]
            tcp_header_length = tcp_header_length & 0xF0
            tcp_header_length = tcp_header_length >> 2

            payload_header = ETH_HLEN + ip_header_length + tcp_header_length
            try:
                payload_str = packet_bytearray[payload_header:(len(packet_bytearray))].decode()
                payload_str = bytes(payload_str,encoding='utf8')
            except:
                pass

            current_Key = http_sessions.Key(ip_src, ip_dst, port_src, port_dst)

            try:
                if ((payload_str[:3] == b'GET') or (payload_str[:4] == b'POST')
                or (payload_str[:4] == b'HTTP') or (payload_str[:3] == b'PUT')
                or (payload_str[:6] == b'DELETE') or (payload_str[:4] == b'HEAD')):

                    if (((payload_str[:3] == b'GET' or payload_str[:4] == b'HEAD' or payload_str[:6] == b'DELETE') and (crlf2_0 in payload_str))
                    or ((payload_str[:4] == b'POST' or payload_str[:3] == b'PUT') and (crlf2 in payload_str) and (crlf2_0 not in payload_str))):
                        #print("3333333333333333333333")
                    #  print(payload_str.decode())
                        print("[*] 原始数据报处理后提取的五元组信息：")
                        print(int2ip(ip_src)+"[{}]".format(str(port_src))+"---->"+int2ip(ip_dst)+"[{}]".format(str(port_dst)))
                        print("-------------------------------------------------------------------------------")
                        print("[*] 原始数据报处理后提取的请求信息：")
                        print("-------------------------------------------------------------------------------")
                        printUntilCRLF(payload_str,'bytestr')
                        print("-------------------------------------------------------------------------------")


                        print("PID\tUID\tCOMM\tCMD")
                        with open(f'/proc/{skb.pid}/comm', 'r') as proc_comm:
                            proc_name = proc_comm.read().rstrip()
                        with open(f'/proc/{skb.pid}/cmdline', 'r') as proc_cmd:
                            proc_cmd = proc_cmd.read().rstrip()
                            print("{}\t{}\t{}\t{}".format(skb.pid,skb.uid,proc_name,proc_cmd))
                            print("-------------------------------------------------------------------------------")


                        try:
                            del http_sessions[current_Key]
                        except:
                            print("error during delete from bpf map")
                    else:

                        http_packet_dictionary[binascii.hexlify(current_Key)] = payload_str
                else:

                    if (current_Key in http_sessions):

                        if (binascii.hexlify(current_Key) in http_packet_dictionary):
                            http_pre_string = http_packet_dictionary[binascii.hexlify(current_Key)]
                            if (crlf not in payload_str):
                                payload_str = http_pre_string + payload_str

                                print("[*] 原始数据报处理后提取的五元组信息：")
                                print(int2ip(ip_src)+"[{}]".format(str(port_src))+"---->"+int2ip(ip_dst)+"[{}]".format(str(port_dst)))
                                print("-------------------------------------------------------------------------------")
                                print("[*] 原始数据报处理后提取的请求信息：")
                                print("-------------------------------------------------------------------------------")
                                printUntilCRLF(payload_str,'bytestr')
                                print("-------------------------------------------------------------------------------")

                                print("PID\tUID\tCOMM\tCMD")
                                with open(f'/proc/{skb.pid}/comm', 'r') as proc_comm:
                                    proc_name = proc_comm.read().rstrip()
                                with open(f'/proc/{skb.pid}/cmdline', 'r') as proc_cmd:
                                    proc_cmd = proc_cmd.read().rstrip()
                                    print("{}\t{}\t{}\t{}".format(skb.pid,skb.uid,proc_name,proc_cmd))
                                    print("-------------------------------------------------------------------------------")
                # log_submit(int2ip(ip_src),port_src,int2ip(ip_dst),port_dst,"TCP",skb.pid,skb.uid,proc_name,proc_cmd)
                                try:
                                    del http_sessions[current_Key]
                                    del http_packet_dictionary[binascii.hexlify(current_Key)]
                                except:
                                    print("[*] error deleting from map or dictionary")
                            else:
                                http_pre_string += payload_str
                                if (len(http_pre_string) > MAX_URL_STRING_LEN):
                                    print("[*] request too large!")
                                    try:
                                        del http_sessions[current_Key]
                                        del http_packet_dictionary[binascii.hexlify(current_Key)]
                                    except:
                                        print("error deleting from map or dict")
                                http_packet_dictionary[binascii.hexlify(current_Key)] = http_pre_string
                        else:
                            try:
                                del http_sessions[current_Key]
                            except:
                                print("error del http_session")
                if (((http_packet_count) % CLEANUP_N_PACKETS) == 0):
                    cleanup(http_sessions)
            except:
                proc_name = skb.comm.decode()
            try:
                log_submit(int2ip(ip_src),port_src,int2ip(ip_dst),port_dst,"HTTP",payload_str,skb.pid,skb.uid,proc_name,proc_cmd)
            except:
                print("Some Exceptions happen during logging.")

class HTTP():

    def __init__(self, global_arg):

        self.bpf_kprobe_http = BPF(src_file = "./http/kprobe_http.c")
        self.bpf_sock_http = BPF(src_file = "./http/http.c")
        self.bpf_kprobe_http.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
        function_http_matching = self.bpf_sock_http.load_func("http_matching", BPF.SOCKET_FILTER)
        BPF.attach_raw_socket(function_http_matching, global_arg.interface)
        socket_fd_http = function_http_matching.sock
        sock_http = socket.fromfd(socket_fd_http,socket.PF_PACKET,  socket.SOCK_RAW,socket.IPPROTO_IP)
        sock_http.setblocking(True)
        global http_sessions
        http_sessions = self.bpf_sock_http.get_table("sessions")
        self.bpf_sock_http["events_http"].open_perf_buffer(print_http)

        print("[*] The HTTP Hook is ready.")

    def http_buffer_poll(self):

        while True:
            try:
                self.bpf_sock_http.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()


def init(global_arg):
    libssl_path = global_arg.libssl_path
    interface = global_arg.interface
    global pid
    pid = global_arg.pid
    http = HTTP(global_arg)
    return http

def run(http):
    http.http_buffer_poll()

