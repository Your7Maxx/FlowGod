from bcc import BPF
import sys


sys.path.append('../utils/')
from tools import *

pid = None
go_https_sessions = None
bpf_kprobe_go_https = None

go_https_packet_count = 0
go_https_packet_dictionary = {}


def print_go_https(cpu,data,size):
    global bpf_kprobe_go_https
    event = bpf_kprobe_go_https["events_go_https"].event(data)
    buf_size = event.len
    payload_str = bytearray(event.buf[:buf_size]).decode()
    payload_bytes_str = bytes(payload_str,encoding='utf-8')

    current_Key = go_https_sessions.Key(event.saddr, event.daddr, event.sport, event.dport)

    if ((payload_bytes_str[:3] == b'GET') or (payload_bytes_str[:4] == b'POST')
            or (payload_bytes_str[:4] == b'HTTP') or (payload_bytes_str[:3] == b'PUT')
            or (payload_bytes_str[:6] == b'DELETE') or (payload_bytes_str[:4] == b'HEAD')):
        if crlf2 in payload_bytes_str:
            print("[*] 原始数据报处理后提取的五元组信息：")
            print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
            print("-------------------------------------------------------------------------------")
            print("[*] 原始数据报处理后提取的请求信息：")
            printUntilCRLF(payload_str,'str')
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
                log_submit(str(int2ip(event.saddr)),str(event.sport),str(int2ip(event.daddr)),str(event.dport),"HTTPS",payload_str,event.pid,event.uid,proc_name,proc_cmd)
            except:
                print("Some Exceptions happen during logging.")

            try:
                del go_https_sessions[current_Key]
            except:
                print("error during delete from bpf map ")

        else:
            go_https_packet_dictionary[binascii.hexlify(current_Key)] = payload_bytes_str

    else:
            if (current_Key in go_https_sessions):
                if (binascii.hexlify(current_Key) in go_https_packet_dictionary):
                    prev_payload_string = go_https_packet_dictionary[binascii.hexlify(current_Key)]
                    if (crlf2 in payload_bytes_str):
                        prev_payload_string += payload_bytes_str
                        print("[*] 原始数据报处理后提取的五元组信息：")
                        print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
                        print("-------------------------------------------------------------------------------")
                        print("[*] 原始数据报处理后提取的请求信息：")
                        printUntilCRLF(prev_payload_string.decode(),'str')
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
                            log_submit(str(int2ip(event.saddr)),str(event.sport),str(int2ip(event.daddr)),str(event.dport),"HTTPS",payload_str,event.pid,event.uid,proc_name,proc_cmd)
                        except:
                            print("Some Exceptions happen during logging.")

                        try:
                            del go_https_sessions[current_Key]
                            del go_https_packet_dictionary[binascii.hexlify(current_Key)]

                        except:
                            print("error deleting from map or dictionary")
                    else:
                        prev_payload_string += payload_bytes_str
                        if (len(prev_payload_string) > MAX_URL_STRING_LEN):
                            print("url too long")
                            try:
                                del go_https_sessions[current_Key]
                                del go_https_packet_dictionary[binascii.hexlify(current_Key)]
                            except:
                                print("error deleting from map or dict")
                        go_https_packet_dictionary[binascii.hexlify(current_Key)] = prev_payload_string
                else:
                    try:
                        del go_https_sessions[current_Key]
                    except:
                        print("error del https_session")

    global go_https_packet_count
    go_https_packet_count += 1
    if (((go_https_packet_count) % CLEANUP_N_PACKETS) == 0):
        cleanup(go_https_sessions)



class GOHTTPS():

    def __init__(self, global_arg):
        self.bpf_uprobe_go_ssl = BPF(src_file = "./gotls/uprobe_go_ssl.c")

        if get_go_version(global_arg.go_program_path):
            self.bpf_uprobe_go_ssl.attach_uprobe(name=global_arg.go_program_path, sym="crypto/tls.(*Conn).writeRecordLocked", fn_name="go_https_register")
        else:
            self.bpf_uprobe_go_ssl.attach_uprobe(name=global_arg.go_program_path, sym="crypto/tls.(*Conn).writeRecordLocked", fn_name="go_https_stack")

        self.bpf_kprobe_go_https = BPF(src_file = "./gotls/https_go_tcp.c")
        self.bpf_kprobe_go_https.attach_kprobe(event="tcp_sendmsg", fn_name="trace_go_tcp_sendmsg")

        global bpf_kprobe_go_https
        bpf_kprobe_go_https = self.bpf_kprobe_go_https
        global go_https_sessions
        go_https_sessions = bpf_kprobe_go_https.get_table("sessions")

        print("[*] The HTTPS Hook for Go is ready.")

    def go_https_buffer_poll(self):
        self.bpf_kprobe_go_https["events_go_https"].open_perf_buffer(print_go_https)
        while True:
            try:
                self.bpf_kprobe_go_https.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()



def init(global_arg):
    libssl_path = global_arg.libssl_path
    interface = global_arg.interface
    global pid
    pid = global_arg.pid
    gohttps = GOHTTPS(global_arg)
    return gohttps

def run(gohttps):
    gohttps.go_https_buffer_poll()

