
                                      ______ _                _____           _ 
                                     |  ____| |              / ____|         | |
                                     | |__  | | _____      _| |  __  ___   __| |
                                     |  __| | |/ _ \ \ /\ / / | |_ |/ _ \ / _` |
                                     | |    | | (_) \ V  V /| |__| | (_) | (_| |
                                     |_|    |_|\___/ \_/\_/  \_____|\___/ \__,_|
✨ FlowGod is a powerful process-level network flow sniffer tool based on eBPF.

## 0x01 食用指南

```
# For Ubuntu20.10+
sudo apt-get install -y  make clang llvm libelf-dev libbpf-dev bpfcc-tools libbpfcc-dev linux-tools-$(uname -r) linux-headers-$(uname -r)

# For RHEL8.2+
sudo yum install libbpf-devel make clang llvm elfutils-libelf-devel bpftool bcc-tools bcc-devel
```

https://github.com/iovisor/bcc/issues/3993

```
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

