import sys

sys.path.append('./user/')
sys.path.append('./utils/')
import user_udp

global_arg = user_udp.Global("all","ens3")

user_udp.run(global_arg)


