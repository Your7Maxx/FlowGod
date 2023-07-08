# FlowGod

FlowGod is a powerful process-level network flow sniffer tool based on eBPF.
```
                                  ______ _                _____           _ 
                                 |  ____| |              / ____|         | |
                                 | |__  | | _____      _| |  __  ___   __| |
                                 |  __| | |/ _ \ \ /\ / / | |_ |/ _ \ / _` |
                                 | |    | | (_) \ V  V /| |__| | (_) | (_| |
                                 |_|    |_|\___/ \_/\_/  \_____|\___/ \__,_|
```
FlowGod supports a variety of common protocols: UDP & TCP & HTTP & HTTPS & DNS (curl/wget/nc/python/go).

## 食用指南
安装`bcc`相关环境和依赖（软件包安装方式）：
```
# For Ubuntu20.10+
sudo apt-get install -y  make clang llvm libelf-dev libbpf-dev bpfcc-tools libbpfcc-dev linux-tools-$(uname -r) linux-headers-$(uname -r)

# For RHEL8.2+
sudo yum install libbpf-devel make clang llvm elfutils-libelf-devel bpftool bcc-tools bcc-devel
```
由于`bcc`版本问题导致程序无法执行，请选择源码编译的方式安装（推荐[0.25.0版本](https://github.com/iovisor/bcc/releases/tag/v0.25.0))，相关issue参考链接：https://github.com/iovisor/bcc/issues/3993
```
# 建议先使用软件包的方式安装bcc，若运行FlowGod程序出现bcc版本问题，可参考下面的命令编译安装合适版本的bcc

apt purge bpfcc-tools libbpfcc python3-bpfcc
wget https://github.com/iovisor/bcc/releases/download/v0.25.0/bcc-src-with-submodule.tar.gz
tar xf bcc-src-with-submodule.tar.gz
cd bcc/
apt install -y python-is-python3
apt install -y bison build-essential cmake flex git libedit-dev   libllvm11 llvm-11-dev libclang-11-dev zlib1g-dev libelf-dev libfl-dev python3-distutils
apt install -y checkinstall
mkdir build
cd build/
cmake -DCMAKE_INSTALL_PREFIX=/usr -DPYTHON_CMD=python3 ..
make
checkinstall
```
具体源码编译安装`bcc`的文档请参考：https://github.com/iovisor/bcc/blob/master/INSTALL.md （推荐）

Python相关包安装：`pip install -r requirements`

## FlowGod参数指南
``` 
  -h, --help            显示FlowGod使用帮助信息并退出
  
  -l LIBSSL_PATH, --libssl LIBSSL_PATH      
                        指定libssl.so相关文件路径，默认为 /lib/x86_64-linux-gnu/libssl.so.3
                  
  -i INTERFACE, --interface INTERFACE    
                        指定需要捕获流量的网卡，默认为ens3
                                        
  -p PID, --pid PID     指定需要捕获的进程，默认捕获所有进程
  
  -f [{udp,http,https,all} ...], --protocol [{udp,http,https,dns,all} ...]      
                        指定需要捕获的协议类型，其中 all 代表 udp+http+https+dns   
                        
  --pyssl               指定需要捕获Python程序发出的HTTPS请求
  
  --gotls GO_PROGRAM_PATH     
                        指定需要捕获Go程序发出的HTTPS请求，并提供Go程序所在文件路径                        
```

## FlowGod使用示例
- 监听pid为1314的进程从eth1网口发出的udp、http和https的请求
```
python3 mygod.py -l /lib/x86_64-linux-gnu/libssl.so.3 -i eth1 -f udp http https -p 1314
```

- 监听pid为1314的进程从eth1网口发出的udp、http和Python程序的https协议请求（目前FlowGod不支持同时指定https和pyssl参数）
```
python3 mygod.py -l /lib/x86_64-linux-gnu/libssl.so.3 -i eth1 -f udp http --pyssl -p 1314
```

- 监听pid为1314的进程从eth1网口发出的udp、http和指定Go程序的https协议请求（目前FlowGod不支持同时指定https和gotls参数）
```
python3 mygod.py -l /lib/x86_64-linux-gnu/libssl.so.3 -i eth1 -f udp http --gotls /path/to/go_program -p 1314
```

- 演示视频   
  （测试环境：Ubuntu 22.04/Kernel 5.15.0-60-generic）   
[![FlowGod使用演示视频](https://i.ytimg.com/vi/W-8VLt-Q4GI/maxresdefault.jpg)](https://youtu.be/W-8VLt-Q4GI "FlowGod使用演示视频")


## 项目借鉴
[1] [bcc官方项目](https://github.com/iovisor/bcc)：examples/tools    
[2] [eCapture(旁观者)](https://github.com/gojue/ecapture): capture SSL/TLS text content without CA cert Using eBPF

- 特别鸣谢：[CFC4N](https://github.com/cfc4n) 在ecapture项目的discussion中对作者的建议和解答

## TODOs
- Dockerfile
- CO-RE
- NIPS
