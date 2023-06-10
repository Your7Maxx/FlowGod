import sys

sys.path.append('./user/')
sys.path.append('./utils/')
import user_https

print(1)
global_arg = user_https.Global("all","ens3","/lib/x86_64-linux-gnu/libssl.so.3")

user_https.run(global_arg)
