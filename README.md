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
FlowGod supports a variety of common protocols: UDP & TCP & HTTP & HTTPS (curl/wget/nc/python).

## 食用指南
安装`bcc`相关环境和依赖（软件包安装方式）：
```
# For Ubuntu20.10+
sudo apt-get install -y  make clang llvm libelf-dev libbpf-dev bpfcc-tools libbpfcc-dev linux-tools-$(uname -r) linux-headers-$(uname -r)

# For RHEL8.2+
sudo yum install libbpf-devel make clang llvm elfutils-libelf-devel bpftool bcc-tools bcc-devel
```
`bcc`版本问题导致程序无法执行，请选择源码编译的方式安装（推荐[0.25.0版本](https://github.com/iovisor/bcc/releases/tag/v0.25.0))，相关issue参考链接：https://github.com/iovisor/bcc/issues/3993
```
# 建议先使用软件包的方式安装bcc，或运行FlowGod程序出现bcc版本问题，可参考下面的命令编译安装合适版本的bcc

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
具体源码编译安装`bcc`的文档请参考：https://github.com/iovisor/bcc/blob/master/INSTALL.md
