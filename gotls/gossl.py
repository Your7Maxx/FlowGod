from bcc import BPF

b = BPF(src_file = "gossl.c")


#b.attach_uprobe(name="/root/go/src/hello/hello",sym="crypto/tls.(*Conn).writeRecordLocked",fn_name="crack_https")
b.attach_uprobe(name="/root/go/src/hello/hello",sym="crypto/tls.(*Conn).writeRecordLocked",fn_name="crack_https")


def print_event(cpu,data,size):
    print("-----------------------------------------------")
   # print("%s\t%s\t" % ("PID","UID"))
    event = b["events"].event(data)
  #  print("%d\t%d\t" % (event.pid,event.uid))
    print("[*]PID: {}".format(event.pid))
    print("[*]UID: {}".format(event.uid))
    print("[*]数据包:")
    print(bytes(event.buf)[:event.len].decode())

    #print("%d\t%d\t%s" % (event.pid,event.uid,event.parm1))

print("---------------------start----------------------")
#print("%s\t%s\t%s" % ("PID","UID","PARM1"))
#b.trace_print()
b["events"].open_perf_buffer(print_event)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()


