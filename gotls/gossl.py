from bcc import BPF
import subprocess
import re
import  sys
import binascii
import time

crlf2 = b'\r\n\r\n'
MAX_URL_STRING_LEN = 8192
CLEANUP_N_PACKETS = 50
MAX_AGE_SECONDS = 30

print("---------------------start----------------------")

def get_go_version(binary_file):
    output = subprocess.check_output(["strings", binary_file]).decode()
    pattern = r"go\d+\.\d+\.\d+"
    matches = re.findall(pattern, output)
    version_nums = matches[0][2:].split('.')
    version_ints = [int(num) for num in version_nums]

    if version_ints < [1,17,0]:
        print("[*]检测到目标程序的go编译版本小于1.17.0")
        return 0
    else:
        print("[*]检测到目标程序的go编译版本大于1.17.0")
        return 1

def int2ip(rawip):
    result = []
    for i in range(4):
        rawip, mod = divmod(rawip, 256)
        result.insert(0,mod)
    return '.'.join(map(str,result))

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

def print_go_https(cpu,data,size):
    print("-----------------------------------------------")
    event = bpf_kprobe_go_https["events_go_https"].event(data)
    buf_size = event.len
    payload_str = bytearray(event.buf[:buf_size]).decode()
    payload_bytes_str = bytes(payload_str,encoding='utf-8')

    current_Key = go_https_sessions.Key(event.saddr, event.daddr, event.sport, event.dport)

    if ((payload_bytes_str[:3] == b'GET') or (payload_bytes_str[:4] == b'POST')
            or (payload_bytes_str[:4] == b'HTTP') or (payload_bytes_str[:3] == b'PUT')
            or (payload_bytes_str[:6] == b'DELETE') or (payload_bytes_str[:4] == b'HEAD')):
        if crlf2 in payload_bytes_str:
            print("[*] 原始数据报处理后提取的ip/端口信息：")
            print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
            print("[*] 原始数据报处理后提取的payload信息：")
            printUntilCRLF(payload_str,'str')
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
                        print("[*] 原始数据报处理后提取的ip/端口信息：")
                        print(str(int2ip(event.saddr))+"[{}]".format(str(event.sport))+"---->"+str(int2ip(event.daddr))+"[{}]".format(str(event.dport)))
                        print("[*] 原始数据报处理后提取的payload信息：")
                        printUntilCRLF(prev_payload_string.decode(),'str')
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

    print("[*]PID: {}".format(event.pid))
    print("[*]UID: {}".format(event.uid))


binary_file = str(sys.argv[1])
bpf_uprobe_go_ssl = BPF(src_file = "uprobe_go_ssl.c")

if get_go_version(binary_file):
    bpf_uprobe_go_ssl.attach_uprobe(name=binary_file,sym="crypto/tls.(*Conn).writeRecordLocked",fn_name="go_https_register")
else:
    bpf_uprobe_go_ssl.attach_uprobe(name=binary_file,sym="crypto/tls.(*Conn).writeRecordLocked",fn_name="go_https_stack")


bpf_kprobe_go_https = BPF(src_file = "https_go_tcp.c")
bpf_kprobe_go_https.attach_kprobe(event="tcp_sendmsg", fn_name="trace_go_tcp_sendmsg")

go_https_sessions = bpf_kprobe_go_https.get_table("sessions")
go_https_packet_count = 0
go_https_packet_dictionary = {}

bpf_kprobe_go_https["events_go_https"].open_perf_buffer(print_go_https)

#b["events_go_https"].open_perf_buffer(print_event)

#bpf_kprobe_go_https.trace_print()


while 1:
    try:
        bpf_kprobe_go_https.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()


