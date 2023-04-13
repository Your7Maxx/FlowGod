import sys

sys.path.append('./user/')
sys.path.append('./utils/')
import user_py_https

global_arg = user_py_https.Global("all","ens3")

user_py_https.run(global_arg)
