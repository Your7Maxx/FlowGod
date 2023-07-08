from bcc import BPF
import socket
import ctypes as ct
import sys

sys.path.append('../utils/')
from tools import *

pid = None
py_https_sessions = None
bpf_kprobe_py_https = None

py_https_packet_count = 0
py_https_packet_dictionary = {}


def print_py_https(cpu,data,size):
    event = bpf_kprobe_py_https["events_py_https"].event(data)
  #  print("%d\n" % event.num)
    current_Key = py_https_sessions.Key(event.saddr, event.daddr, event.sport, event.dport)
    #print(event.buf)
    #print("[*] 原始数据报处理后提取的ip/端口信息：")
   #print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
    payload_str = event.buf[:]
   # print(payload_str)
    if ((payload_str[:3] == b'GET') or (payload_str[:4] == b'HEAD') or (payload_str[:6] == b'DELETE')):
        if payload_str[-4:] == crlf2:
            print("[HTTPS_PY] 原始数据报处理后提取的五元组信息：")
            print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
            print("-------------------------------------------------------------------------------")
            print("[HTTPS_PY] 原始数据报处理后提取的请求信息：")
            printUntilCRLF(payload_str, 'bytestr')
            print("-------------------------------------------------------------------------------")

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
                del py_https_sessions[current_Key]
            except:
                print("error during delete from bpf map")
        else:
            py_https_packet_dictionary[binascii.hexlify(current_Key)] = payload_str

    elif ((payload_str[:4] == b'POST') or (payload_str[:3] == b'PUT')):

        if payload_str[-4:] == crlf2:
            for header in payload_str.split(b'\r\n'):
                if b'Content-Length' in header:
                    if header.split(b': ')[1] == b'0':
                        print("[*] 原始数据报处理后提取的ip/端口信息：")
                        print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
                        print("-------------------------------------------------------------------------------")
                        print("[*] 原始数据报处理后提取的payload信息：")
                        printUntilCRLF(payload_str,'bytestr')
                        print("-------------------------------------------------------------------------------")
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

                        log_submit(str(int2ip(event.saddr)),str(event.sport),str(int2ip(event.daddr)),str(event.dport),"HTTPS",payload_str,event.pid,event.uid,proc_name,proc_cmd)
                    else:
                        py_https_packet_dictionary[binascii.hexlify(current_Key)] = payload_str
        else:
            print("nb")

    else:

        if (current_Key in py_https_sessions):

            if (binascii.hexlify(current_Key) in py_https_packet_dictionary):

                prev_payload_string = py_https_packet_dictionary[binascii.hexlify(current_Key)]
                if (crlf not in payload_str):

                    prev_payload_string += payload_str
                    print("[*] 原始数据报处理后提取的ip/端口信息：")
                    print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
                    print("-------------------------------------------------------------------------------")
                    print("[*] 原始数据报处理后提取的payload信息：")
                    printUntilCRLF(prev_payload_string, 'bytestr')
                    print("-------------------------------------------------------------------------------")
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

                    log_submit(str(int2ip(event.saddr)),str(event.sport),str(int2ip(event.daddr)),str(event.dport),"HTTPS",prev_payload_string,event.pid,event.uid,proc_name,proc_cmd)

                    try:
                        del py_https_sessions[current_Key]
                        del py_https_packet_dictionary[binascii.hexlify(current_Key)]
                    except:
                        print("error deleting from map or dictionary")
                else:

                    prev_payload_string += payload_str
                    if (len(prev_payload_string) > MAX_URL_STRING_LEN):
                        print("url too long")
                        try:
                            del py_https_sessions[current_Key]
                            del py_https_packet_dictionary[binascii.hexlify(current_Key)]
                        except:
                            print("error deleting from map or dict")
                    py_https_packet_dictionary[binascii.hexlify(current_Key)] = prev_payload_string
            else:

                try:
                    del py_https_sessions[current_Key]
                except:
                    print("error del bpf_session")

    global py_https_packet_count
    py_https_packet_count += 1
    #print(https_packet_count)
    if (((py_https_packet_count) % CLEANUP_N_PACKETS) == 0):
        cleanup(py_https_sessions)



class Global():
    def __init__(self, pid, interface):
        self.pid = pid
        self.interface = interface

class PYHTTPS():

    def __init__(self, global_arg):

        self.bpf_uprobe_py_ssl = BPF(src_file = "./https/uprobe_py_ssl.c")
        self.bpf_uprobe_py_ssl.attach_uprobe(name=global_arg.libssl_path, sym="SSL_write_ex",fn_name="probe_SSL_rw_ex_enter")
        self.bpf_kprobe_py_https = BPF(src_file = "./https/https_py_tcp.c")
        self.bpf_kprobe_py_https.attach_kprobe(event="tcp_sendmsg", fn_name="trace_py_tcp_sendmsg")

        global bpf_kprobe_py_https
        bpf_kprobe_py_https = self.bpf_kprobe_py_https
        global py_https_sessions
        py_https_sessions = self.bpf_kprobe_py_https.get_table("sessions")

        print("[*] The HTTPS Hook for Python is ready.")

    def py_https_buffer_poll(self):
        self.bpf_kprobe_py_https["events_py_https"].open_perf_buffer(print_py_https)
        while True:
            try:
                self.bpf_kprobe_py_https.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()



def init(global_arg):
    libssl_path = global_arg.libssl_path
    interface = global_arg.interface
    global pid
    pid = global_arg.pid
    pyhttps = PYHTTPS(global_arg)
    return pyhttps

def run(pyhttps):
    pyhttps.py_https_buffer_poll()


