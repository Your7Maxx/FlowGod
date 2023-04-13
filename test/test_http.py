import sys

sys.path.append('./user/')
sys.path.append('./utils/')
import user_http

global_arg = user_http.Global("all","ens3")
print(1)
user_http.run(global_arg)
