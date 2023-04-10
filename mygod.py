from bcc import BPF
import sys
import socket
import os
import binascii
import calendar
from datetime import datetime
import time
import ctypes as ct
from time import sleep, ctime
import threading
import socket

CLEANUP_N_PACKETS = 50     # cleanup every CLEANUP_N_PACKETS packets received
MAX_URL_STRING_LEN = 8192  # max url string len (usually 8K)
MAX_AGE_SECONDS = 30
ETH_HLEN = 14
UDP_HLEN = 8
crlf2 = b'\r\n\r\n'
crlf2_0 = b'\r\n\r\n\x00'
crlf = b'\r\n'

yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'

version = 'v0.1.0'
message = white + '{' + red + version + ' #dev' + white + '}'

Flowgod_banner = f"""
FlowGod is a powerful process-level network flow sniffer tool{yellow}
  ______ _                _____           _ {blue}
 |  ____| |              / ____|         | |{blue}
 | |__  | | _____      _| |  __  ___   __| |{blue}
 |  __| | |/ _ \ \ /\ / / | |_ |/ _ \ / _` |{blue}
 | |    | | (_) \ V  V /| |__| | (_) | (_| |{blue}
 |_|    |_|\___/ \_/\_/  \_____|\___/ \__,_|{message}{green}

{red}[+] FlowGod supports a variety of common protocols:UDP & TCP & HTTP & HTTPS{end}
{red}[+] Flowgod stores the captured traffic logs at ./log/flow.log {end}

"""


def int2ip(rawip):
    result = []
    for i in range(4):
        rawip, mod = divmod(rawip, 256)
        result.insert(0,mod)
    return '.'.join(map(str,result))

    def is_dns_query(packet_str):
    ip_src_str = packet_str[ETH_HLEN + 12: ETH_HLEN + 16]  # ip source offset 12..15
    ip_dst_str = packet_str[ETH_HLEN + 16:ETH_HLEN + 20]   # ip dest   offset 16..19

    ip_src = int.from_bytes(ip_src_str,"big")
    ip_dst = int.from_bytes(ip_dst_str,"big")
    if int2ip(ip_dst) == '114.114.114.114':
        return True
    else:
        return False

def printUntilCRLF(s,type):
    if type == 'str':
        crlf = '\r\n'
        s = s.split(crlf)
        for i in range(len(s)):
            print(s[i])

    elif type == 'bytestr':
        crlf = b'\r\n'
        s = s.split(crlf)
        for i in range(len(s)):
            print(s[i].decode())

def cleanup(bpf_sessions):
    # get current time in seconds
    current_time = int(time.time())
    # looking for leaf having:
    # timestap  == 0        --> update with current timestamp
    # AGE > MAX_AGE_SECONDS --> delete item
    for key, leaf in bpf_sessions.items():
        try:
            current_leaf = bpf_sessions[key]
            # set timestamp if timestamp == 0
            if (current_leaf.timestamp == 0):
                bpf_sessions[key] = bpf_sessions.Leaf(current_time)
            else:
                # delete older entries
                if (current_time - current_leaf.timestamp > MAX_AGE_SECONDS):
                    del bpf_sessions[key]
        except:
            print("cleanup exception.")
    return


def log_submit(sip,sport,dip,dport,protocal,pid,uid,comm,cmd):
    now = datetime.now()
    dt_string = str(now.strftime("%Y %m %d %H:%M:%S"))
    dt_str = dt_string.split(" ")

    if list(dt_string.split(" ")[1])[0] == '0':
        mon = int(list(dt_string.split(" ")[1])[1])
        dt_str[1] = calendar.month_abbr[mon]
    else:
        mon = int(dt_string.split(" ")[1])
        dt_str[1] = calendar.month_abbr[mon]

    dt_str_final = " ".join(str(i) for i in dt_str)

    data = {"sip":sip,
            "sport":sport,
            "dip":dip,
            "dport":dport,
            "protocal":protocal,
            "pid":pid,
            "uid":uid,
            "comm":comm,
            "cmd":cmd}

   # print(str(data))
    bpf_event_log = dt_str_final + '  ebpf: ebpf_data: ' + str(data) + '\n'

    with open('./log/flow.log','a') as fd:
        fd.write(bpf_event_log)

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

        payload_str = packet_bytearray[payload_header:(len(packet_bytearray))].decode()
        payload_str = bytes(payload_str,encoding='utf8')

        current_Key = http_sessions.Key(ip_src, ip_dst, port_src, port_dst)
        #print('1111111111111111111111')
       # print(payload_str)
        try:
            if ((payload_str[:3] == b'GET') or (payload_str[:4] == b'POST')
            or (payload_str[:4] == b'HTTP') or (payload_str[:3] == b'PUT')
            or (payload_str[:6] == b'DELETE') or (payload_str[:4] == b'HEAD')):
                #print("222222222222222222222")
                if (((payload_str[:3] == b'GET' or payload_str[:4] == b'HEAD' or payload_str[:6] == b'DELETE') and (crlf2_0 in payload_str))
                or ((payload_str[:4] == b'POST' or payload_str[:3] == b'PUT') and (crlf2 in payload_str) and (crlf2_0 not in payload_str))):
                    #print("3333333333333333333333")
                  #  print(payload_str.decode())
                    print("[*] 原始数据报处理后提取的payload信息：")
                    print("-------------------------------------------------------------------------------")
                    printUntilCRLF(payload_str,'bytestr')
                    print("-------------------------------------------------------------------------------")
                    print("[*] 原始数据报处理后提取的ip/端口信息：")
                    print(int2ip(ip_src)+"[{}]".format(str(port_src))+"---->"+int2ip(ip_dst)+"[{}]".format(str(port_dst)))
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
                    except:
                        print("error during delete from bpf map")
                else:
                 #   print("3333333333")
                    http_packet_dictionary[binascii.hexlify(current_Key)] = payload_str
            else:
                #print("44444444")
                if (current_Key in http_sessions):
                    #print("555555555")
                    if (binascii.hexlify(current_Key) in http_packet_dictionary):
                        http_pre_string = http_packet_dictionary[binascii.hexlify(current_Key)]
                        if (crlf not in payload_str):
                            payload_str = http_pre_string + payload_str
                            print("[*] 原始数据报处理后提取的payload信息：")
                            print("-------------------------------------------------------------------------------")
                            printUntilCRLF(payload_str,'bytestr')
                            print("-------------------------------------------------------------------------------")
                            print("[*] 原始数据报处理后提取的ip/端口信息：")
                            print(int2ip(ip_src)+"[{}]".format(str(port_src))+"---->"+int2ip(ip_dst)+"[{}]".format(str(port_dst)))
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
    if not is_dns_query(packet_str): # 暂时排除dns请求
        packet_bytearray = bytearray(packet_str)
        print("[*] bcc前端捕获到的原始数据报:")
        print(packet_bytearray)

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

        print("[*] 原始数据报处理后提取的ip/端口信息：")
        print(int2ip(ip_src)+"[{}]".format(port_src)+"---->"+int2ip(ip_dst)+"[{}]".format(port_dst))

        payload_header = ETH_HLEN + ip_header_length + UDP_HLEN
        print("[*] 原始数据报处理后提取的payload信息：")
        payload_str = packet_str[payload_header:(len(packet_bytearray))]

        print("-------------------------------------------------------------------------------")
        try:
            payload_str = bytearray(payload_str).decode('utf-8')
            print(payload_str)
            print("-------------------------------------------------------------------------------")
            print("PID\tUID\tCOMM\tCMD")
            with open(f'/proc/{skb.pid}/comm', 'r') as proc_comm:
                proc_name = proc_comm.read().rstrip()
            with open(f'/proc/{skb.pid}/cmdline', 'r') as proc_cmd:
                proc_cmd = proc_cmd.read().rstrip()
                print("{}\t{}\t{}\t{}".format(skb.pid,skb.uid,proc_name,proc_cmd))
                print("-------------------------------------------------------------------------------")
               # log_submit(int2ip(ip_src),port_src,int2ip(ip_dst),port_dst,"UDP",skb.pid,skb.uid,proc_name,proc_cmd)

        except:
            proc_name = skb.comm.decode()

def print_https(cpu, data, size,):
    event = bpf_kprobe_https["events_https"].event(data)
    buf_size = event.len

    if event.buf_filled == 1:
        payload_str = bytearray(event.buf[:buf_size]).decode()
        payload_bytes_str = bytes(payload_str,encoding='utf-8')
        print(payload_bytes_str)

        current_Key = https_sessions.Key(event.saddr, event.daddr, event.sport, event.dport)

        if ((payload_bytes_str[:3] == b'GET') or (payload_bytes_str[:4] == b'POST')
            or (payload_bytes_str[:4] == b'HTTP') or (payload_bytes_str[:3] == b'PUT')
            or (payload_bytes_str[:6] == b'DELETE') or (payload_bytes_str[:4] == b'HEAD')):
            if crlf in payload_bytes_str:
                print("[*] 原始数据报处理后提取的ip/端口信息：")
                print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
                print("[*] 原始数据报处理后提取的payload信息：")
                printUntilCRLF(payload_str,'str')
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
                        print("[*] 原始数据报处理后提取的ip/端口信息：")
                        print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
                        print("[*] 原始数据报处理后提取的payload信息：")
                        printUntilCRLF(prev_payload_string.decode(),'str')
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
    #log_submit(str(int2ip(event.saddr)),str(event.sport),str(int2ip(event.daddr)),str(event.dport),"HTTPS",event.pid,event.uid,proc_name,proc_cmd)

'''
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
            print("[*] 原始数据报处理后提取的ip/端口信息：")
            print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
            print("-------------------------------------------------------------------------------")
            print("[*] 原始数据报处理后提取的payload信息：")
            printUntilCRLF(payload_str)
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
                        printUntilCRLF(payload_str)
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
                    printUntilCRLF(prev_payload_string)
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
'''


# udp
bpf_kprobe_udp = BPF(src_file = "./udp/kprobe_udp.c")
bpf_sock_udp = BPF(src_file = "./udp/udp.c")
bpf_kprobe_udp.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
function_udp_matching = bpf_sock_udp.load_func("udp_matching", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(function_udp_matching, 'ens3')
socket_fd_udp = function_udp_matching.sock
sock_udp = socket.fromfd(socket_fd_udp,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
sock_udp.setblocking(True)

bpf_sock_udp["events_udp"].open_perf_buffer(print_udp)



# http
bpf_kprobe_http = BPF(src_file = "./http/kprobe_http.c")
bpf_sock_http = BPF(src_file = "./http/http.c")
bpf_kprobe_http.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
function_http_matching = bpf_sock_http.load_func("http_matching", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(function_http_matching, 'ens3')
socket_fd_http = function_http_matching.sock
sock_http = socket.fromfd(socket_fd_http,socket.PF_PACKET,  socket.SOCK_RAW,socket.IPPROTO_IP)
sock_http.setblocking(True)

http_sessions = bpf_sock_http.get_table("sessions")
http_packet_count = 0
http_packet_dictionary = {}
bpf_sock_http["events_http"].open_perf_buffer(print_http)



# https
bpf_uprobe_ssl = BPF(src_file = "./https/uprobe_ssl.c")
bpf_uprobe_ssl.attach_uprobe(name="ssl", sym="SSL_write",fn_name="probe_SSL_rw_enter")
bpf_uprobe_ssl.attach_uretprobe(name="ssl", sym="SSL_write",fn_name="probe_SSL_write_exit")
bpf_kprobe_https = BPF(src_file = "./https/myhttps.c")
bpf_kprobe_https.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")

https_sessions = bpf_kprobe_https.get_table("sessions")
https_packet_count = 0
https_packet_dictionary = {}
bpf_kprobe_https["events_https"].open_perf_buffer(print_https)


# https for python
'''
bpf_uprobe_py_ssl = BPF(src_file = "./https/uprobe_py_ssl.c")
bpf_uprobe_py_ssl.attach_uprobe(name="ssl", sym="SSL_write_ex",fn_name="probe_SSL_rw_ex_enter")
bpf_kprobe_py_https = BPF(src_file = "./https/https_py_tcp.c")
bpf_kprobe_py_https.attach_kprobe(event="tcp_sendmsg", fn_name="trace_py_tcp_sendmsg")

py_https_sessions = bpf_kprobe_py_https.get_table("sessions")
py_https_packet_count = 0
py_https_packet_dictionary = {}
bpf_kprobe_py_https["events_py_https"].open_perf_buffer(print_py_https)
'''


def udp_buffer_poll():
    while True:
        try:
            bpf_sock_udp.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


def http_buffer_poll():
    while True:
        try:
            bpf_sock_http.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

def https_buffer_poll():
    while True:
        try:
            bpf_kprobe_https.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

'''
def py_https_buffer_poll():
    while True:
        try:
            bpf_kprobe_py_https.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
'''


if __name__ == '__main__':
    threads = []
    t1 = threading.Thread(target=udp_buffer_poll)
    t2 = threading.Thread(target=http_buffer_poll)
    t3 = threading.Thread(target=https_buffer_poll)
    #t4 = threading.Thread(target=py_https_buffer_poll)

    threads.append(t1)
    threads.append(t2)
    threads.append(t3)
   # threads.append(t4)

    print(Flowgod_banner)
    print("--------------------------------------Start------------------------------------")

    for i in range(3):
        threads[i].start()
    for i in range(3):
        threads[i].join()
