import argparse
import sys
import threading

yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'

version = 'v0.1.0'
message = white + '{' + red + version + ' #dev' + white + '}'

Flowgod_banner = f"""
FlowGod is a powerful process-level network flow sniffer tool{blue}
  ______ _                _____           _ {blue}
 |  ____| |              / ____|         | |{blue}
 | |__  | | _____      _| |  __  ___   __| |{blue}
 |  __| | |/ _ \ \ /\ / / | |_ |/ _ \ / _` |{blue}
 | |    | | (_) \ V  V /| |__| | (_) | (_| |{blue}
 |_|    |_|\___/ \_/\_/  \_____|\___/ \__,_|{message}{green}

{green}[+] FlowGod supports a variety of common protocols:UDP & TCP & HTTP & HTTPS{end}
{green}[+] Flowgod stores the captured traffic logs at ./log/flow.log {end}
"""


parser = argparse.ArgumentParser(description='[*] Please install and deploy the bcc environment before using FlowGod and confirm your libssl path!',
                                 usage='python3 mygod.py [options]\nUse examples:\n\
                                    python3 mygod.py -h [--help] \n\
                                    python3 mygod.py -l /lib/x86_64-linux-gnu/libssl.so.3 -i ens33\n\
                                    python3 mygod.py -i ens33 -p 1234\n\
                                    python3 mygod.py -i ens33 -f udp http https\n\
                                    python3 mygod.py -i ens33 -f all\n\
                                    python3 mygod.py -i ens33 --pyssl\n\
                                    python3 mygod.py -f udp http --gotls /path/to/go_program\n\
                                    \t\t\t......')

parser.add_argument('-l', '--libssl' , type=str, dest='libssl_path', default='/lib/x86_64-linux-gnu/libssl.so.3',
                    help= 'Choose the libssl.so file path, default [/lib/x86_64-linux-gnu/libssl.so.3]')

parser.add_argument('-i', '--interface', type=str, default='ens3', dest='interface',
                    help= 'Choose the interface you want to capture, default [ens33]')

parser.add_argument('-p','--pid', type=str, default='all', dest='pid',
                    help= 'Choose the pid you want to capture, default [all]')

parser.add_argument('-f','--protocol', nargs='*', choices=['udp','http','https','all'], action='append', dest='protocal', required=True,
                    help= 'Choose the protocals you want to capture')

parser.add_argument('--pyssl', action="store_true", dest='pyssl',
                    help= 'Choose if you want to capture HTTPS request from python programs')

parser.add_argument('--gotls', type=str, dest='go_program_path', default='None',
                    help= 'Choose if you want to capture HTTPS request from the specified go program')

#获得传入的参数
args = parser.parse_args()

print(Flowgod_banner)

sys.path.append('./utils/')
from tools import *

global_arg = Global(args.libssl_path, args.interface, args.pid, args.go_program_path)

print("[*] FlowGod is starting ...")
print("[*] FlowGod will work with the following parameters：")
print(f"{green}[+] Libssl_path: " + str(global_arg.libssl_path))
print(f"{green}[+] Interface: " + str(global_arg.interface))
print(f"{green}[+] Process: [pid] " + str(global_arg.pid))
print(f"{green}[+] protocal: " + str(args.protocal[0]))
print(f"{green}[+] pyssl: " + str(args.pyssl))
print(f"{green}[+] gotls: " + str(global_arg.go_program_path))


sys.path.append('./user/')
import user_go_https, user_http, user_https, user_py_https, user_udp


protocal_dict = {'udp':user_udp,
                 'http':user_http,
                 'https':user_https,
                 'pyhttps':user_py_https,
                 'gohttps':user_go_https,
                 }



if args.pyssl and args.go_program_path != 'None':
  print("[!] FlowGod does not support the composite form of HTTPS capture !")
  print("    Such as: python3 mygod.py -f https --pyssl ")
  print("             python3 mygod.py -f https --gotls /path/to/go_program ")
  print("             python3 mygod.py --pyssl --gotls /path/to/go_program ")

else:

  if 'all' in args.protocal[0]:

    if args.pyssl or args.go_program_path != 'None':

      print("[!] FlowGod does not support the composite form of HTTPS capture !")
      print("    Such as: python3 mygod.py -f https --pyssl ")
      print("             python3 mygod.py -f https --gotls /path/to/go_program ")
      print("             python3 mygod.py --gotls /path/to/go_program ")

    else:
      print("[|] Wait for loading eBPF hooks...")

      udp = protocal_dict['udp'].init(global_arg)
      http = protocal_dict['http'].init(global_arg)
      https = protocal_dict['https'].init(global_arg)

      print("--------------------------------------Start------------------------------------")

      threads = []

      t1 = threading.Thread(target=user_udp.run, kwargs={"udp": udp})
      t2 = threading.Thread(target=user_http.run, kwargs={"http": http})
      t3 = threading.Thread(target=user_https.run, kwargs={"https": https})

      threads.append(t1)
      threads.append(t2)
      threads.append(t3)

      for i in range(3):
        threads[i].start()

      for i in range(3):
        threads[i].join()

  else:

    if ('https' in args.protocal[0] and args.pyssl) or \
       ('https' in args.protocal[0] and args.go_program_path != 'None'):
      print("[!] FlowGod does not support the composite form of HTTPS capture !")
      print("    Such as: python3 mygod.py -f https --pyssl ")
      print("             python3 mygod.py -f https --gotls /path/to/go_program ")
      print("             python3 mygod.py --gotls /path/to/go_program ")

    else:

      if args.pyssl: # python + ex_https
        var = locals()

        threads = []
        threads_len = len(args.protocal[0]) + 1

        print("[|] Wait for loading eBPF hooks...")

        for protocal in args.protocal[0]:
          protocal_str = protocal
          var[protocal] = protocal_dict[protocal].init(global_arg)
          var[protocal_str] = threading.Thread(target=protocal_dict[protocal].run, kwargs={protocal_str: var[protocal]})

          threads.append(var[protocal_str])

        pyhttps = protocal_dict['pyhttps'].init(global_arg)
        th_py = threading.Thread(target=user_py_https.run, kwargs={'pyhttps': pyhttps})
        threads.append(th_py)

        for i in range(threads_len):
          threads[i].start()

        print("--------------------------------------Start------------------------------------")

        for i in range(threads_len):
          threads[i].join()


      elif args.go_program_path != 'None': # go + ex_https
        var = locals()

        threads = []
        threads_len = len(args.protocal[0]) + 1

        print("[|] Wait for loading eBPF hooks...")

        for protocal in args.protocal[0]:
          protocal_str = protocal
          var[protocal] = protocal_dict[protocal].init(global_arg)
          var[protocal_str] = threading.Thread(target=protocal_dict[protocal].run, kwargs={protocal_str: var[protocal]})

          threads.append(var[protocal_str])

        gohttps = protocal_dict['gohttps'].init(global_arg)
        th_go = threading.Thread(target=user_go_https.run, kwargs={'gohttps': gohttps})
        threads.append(th_go)

        for i in range(threads_len):
          threads[i].start()

        print("--------------------------------------Start------------------------------------")

        for i in range(threads_len):
          threads[i].join()


      else:
        var = locals()

        threads = []
        threads_len = len(args.protocal[0])

        print("[|] Wait for loading eBPF hooks...")

        for protocal in args.protocal[0]:
          protocal_str = protocal
          var[protocal] = protocal_dict[protocal].init(global_arg)
          var[protocal_str] = threading.Thread(target=protocal_dict[protocal].run, kwargs={protocal_str: var[protocal]})

          threads.append(var[protocal_str])

        for i in range(threads_len):
          threads[i].start()

        print("--------------------------------------Start------------------------------------")

        for i in range(threads_len):
          threads[i].join()












