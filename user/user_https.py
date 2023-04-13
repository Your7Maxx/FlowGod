from bcc import BPF
import socket
import ctypes as ct
import sys

sys.path.append('../utils/')
from tools import *

pid = None
https_sessions = None
bpf_kprobe_https = None

https_packet_count = 0
https_packet_dictionary = {}

def print_https(cpu, data, size,):

    event = bpf_kprobe_https["events_https"].event(data)
    buf_size = event.len

    global pid
    if pid == 'all' or pid == event.pid:
        if event.buf_filled == 1:
            payload_str = bytearray(event.buf[:buf_size]).decode()
            payload_bytes_str = bytes(payload_str,encoding='utf-8')

            current_Key = https_sessions.Key(event.saddr, event.daddr, event.sport, event.dport)

            if ((payload_bytes_str[:3] == b'GET') or (payload_bytes_str[:4] == b'POST')
                or (payload_bytes_str[:4] == b'HTTP') or (payload_bytes_str[:3] == b'PUT')
                or (payload_bytes_str[:6] == b'DELETE') or (payload_bytes_str[:4] == b'HEAD')):
                if crlf in payload_bytes_str:
                    print("[*] 原始数据报处理后提取的ip/端口信息：")
                    print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
                    print("-------------------------------------------------------------------------------")
                    print("[*] 原始数据报处理后提取的payload信息：")
                    printUntilCRLF(payload_str,'str')
                    print("-------------------------------------------------------------------------------")

                    try:
                        del https_sessions[current_Key]
                    except:
                        print("error during delete from bpf map ")
                else:
                    https_packet_dictionary[binascii.hexlify(current_Key)] = payload_bytes_str
            else:
                if (current_Key in https_sessions):
                    if (binascii.hexlify(current_Key) in https_packet_dictionary):
                        prev_payload_string = https_packet_dictionary[binascii.hexlify(current_Key)]
                        if (crlf in payload_bytes_str):
                            prev_payload_string += payload_bytes_str
                            print("[*] 原始数据报处理后提取的五元组信息：")
                            print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
                            print("-------------------------------------------------------------------------------")
                            print("[*] 原始数据报处理后提取的请求信息：")
                            printUntilCRLF(prev_payload_string.decode(),'str')
                            print("-------------------------------------------------------------------------------")

                            try:
                                del https_sessions[current_Key]
                                del https_packet_dictionary[binascii.hexlify(current_Key)]

                            except:
                                print("error deleting from map or dictionary")
                        else:
                            prev_payload_string += payload_bytes_str
                            if (len(prev_payload_string) > MAX_URL_STRING_LEN):
                                print("url too long")
                                try:
                                    del https_sessions[current_Key]
                                    del https_packet_dictionary[binascii.hexlify(current_Key)]
                                except:
                                    print("error deleting from map or dict")
                            https_packet_dictionary[binascii.hexlify(current_Key)] = prev_payload_string
                    else:
                        try:
                            del https_sessions[current_Key]
                        except:
                            print("error del https_session")
            global https_packet_count
            https_packet_count += 1
            #print(https_packet_count)
            if (((https_packet_count) % CLEANUP_N_PACKETS) == 0):
                cleanup(https_sessions)
            #print(t)
        else:
            buf_size = 0
            buf = b""

        print("PID\tUID\tCOMM\tCMD")
        try:
            with open(f'/proc/{event.pid}/comm', 'r') as proc_comm:
                proc_name = proc_comm.read().rstrip()
                with open(f'/proc/{event.pid}/cmdline', 'r') as proc_cmd:
                    proc_cmd = proc_cmd.read().rstrip()
                    print("{}\t{}\t{}\t{}".format(event.pid,event.uid,proc_name,proc_cmd))
                    print("-------------------------------------------------------------------------------")
        except:
            proc_name = "NULL"
        try:
            log_submit(str(int2ip(event.saddr)),str(event.sport),str(int2ip(event.daddr)),str(event.dport),"HTTPS",payload_bytes_str,event.pid,event.uid,proc_name,proc_cmd)
        except:
            print("Some Exceptions happen during logging.")


class HTTPS():

    def __init__(self, global_arg):

        self.bpf_uprobe_ssl = BPF(src_file = "./https/uprobe_ssl.c")
        self.bpf_uprobe_ssl.attach_uprobe(name=global_arg.libssl_path, sym="SSL_write",fn_name="probe_SSL_rw_enter")
        self.bpf_uprobe_ssl.attach_uretprobe(name=global_arg.libssl_path, sym="SSL_write",fn_name="probe_SSL_write_exit")

        self.bpf_kprobe_https = BPF(src_file = "./https/original_https.c")
        self.bpf_kprobe_https.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
        global bpf_kprobe_https
        bpf_kprobe_https = self.bpf_kprobe_https
        global https_sessions
        https_sessions = self.bpf_kprobe_https.get_table("sessions")

        print("[*] The HTTPS Hook is ready.")

    def https_buffer_poll(self):
        self.bpf_kprobe_https["events_https"].open_perf_buffer(print_https)
        while True:
            try:
                self.bpf_kprobe_https.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()

def init(global_arg):
    libssl_path = global_arg.libssl_path
    interface = global_arg.interface
    global pid
    pid = global_arg.pid

    https = HTTPS(global_arg)
    return https


def run(https):
    https.https_buffer_poll()


