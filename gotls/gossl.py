from bcc import BPF
import subprocess
import re
import  sys

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

def print_event(cpu,data,size):
    print("-----------------------------------------------")
   # print("%s\t%s\t" % ("PID","UID"))
    event = b["events"].event(data)
  #  print("%d\t%d\t" % (event.pid,event.uid))
    print("[*]PID: {}".format(event.pid))
    print("[*]UID: {}".format(event.uid))
    print("[*]数据包:")
    print(bytes(event.buf)[:event.len].decode())

binary_file = str(sys.argv[1])

b = BPF(src_file = "gossl.c")

if get_go_version(binary_file):
    b.attach_uprobe(name=binary_file,sym="crypto/tls.(*Conn).writeRecordLocked",fn_name="go_https_register")
else:
    b.attach_uprobe(name=binary_file,sym="crypto/tls.(*Conn).writeRecordLocked",fn_name="go_https_stack")



b["events"].open_perf_buffer(print_event)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()


