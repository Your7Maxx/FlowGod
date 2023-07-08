import sys
import calendar
from datetime import datetime
import time
import subprocess
import re
import binascii
import dnslib

crlf2 = b'\r\n\r\n'
crlf2_0 = b'\r\n\r\n\x00'
crlf = b'\r\n'
ETH_HLEN = 14
UDP_HLEN = 8

CLEANUP_N_PACKETS = 50     # cleanup every CLEANUP_N_PACKETS packets received
MAX_URL_STRING_LEN = 8192  # max url string len (usually 8K)
MAX_AGE_SECONDS = 30



class Global():
    def __init__(self, libssl_path, interface, pid, go_program_path):
        self.libssl_path = libssl_path
        self.interface = interface
        self.pid = pid
        self.go_program_path = go_program_path


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


def log_submit(sip,sport,dip,dport,protocal,request,pid,uid,comm,cmd):
    try:
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
                "request":request,
                "pid":pid,
                "uid":uid,
                "comm":comm,
                "cmd":cmd}

    # print(str(data))
        bpf_event_log = dt_str_final + '  ebpf: ebpf_data: ' + str(data) + '\n'

        with open('./log/flow.log','a') as fd:
            fd.write(bpf_event_log)

    except IOError:
        with open('./log/flow.log','w') as fd:
            fd.write(bpf_event_log)
    except:
        print("Error during logging.")


def get_go_version(binary_file):
    output = subprocess.check_output(["strings", binary_file]).decode()
    pattern = r"go\d+\.\d+\.\d+"
    matches = re.findall(pattern, output)
    version_nums = matches[0][2:].split('.')
    version_ints = [int(num) for num in version_nums]

    if version_ints < [1,17,0]:
        print("[*] 检测到目标程序的go编译版本小于1.17.0")
        return 0
    else:
        print("[*] 检测到目标程序的go编译版本大于1.17.0")
        return 1

def cleanup(bpf_sessions):
    current_time = int(time.time())
    for key, leaf in bpf_sessions.items():
        try:
            current_leaf = bpf_sessions[key]
            if (current_leaf.timestamp == 0):
                bpf_sessions[key] = bpf_sessions.Leaf(current_time)
            else:
                # delete older entries
                if (current_time - current_leaf.timestamp > MAX_AGE_SECONDS):
                    del bpf_sessions[key]
        except:
            print("cleanup exception.")
    return
