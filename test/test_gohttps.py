import sys


sys.path.append('./utils/')
import tools

global_arg = tools.Global("all","ens3","all","/root/go/src/hello/hello_1.20.2")

sys.path.append('./user/')
import user_go_https

gohttps = user_go_https.init(global_arg)
user_go_https.run(gohttps)
