# In Router

以Cisco RW110型号(18MB flash)为例：UART接入获取shell.

关键命令：

+ 传入：wget
+ 传出：无

需要向路由器传入tcpdump 和 netcat 进行后续的抓包

```bash
Linux RV110W 2.6.22 #1 Wed Feb 24 16:16:48 CST 2016 mips unknown
```

交叉编译环境：buildroot-2018

+ 配置buildroot：make menuconfig中指定架构，即Target Architecture。kernel headers设置为自己主机的Linux版本

+ 环境：sudo apt-get install texinfo flex bison libncursesn5-dev patch gettext g++  
+ 编译成功后工具库：buildroot/output/host/usr/bin



## Tcpdump

源码：[Old releases | TCPDUMP/LIBPCAP public repository](https://www.tcpdump.org/old_releases.html)

因为该路由器上Linux版本为2016年的所以下载年份相近的源码进行编译，以防兼容问题

> ### Tcpdump
>
> **Version:** 4.9.1
> **Release Date:** July 23, 2017
> **Download:** [tcpdump-4.9.1.tar.gz](https://www.tcpdump.org/release/tcpdump-4.9.1.tar.gz) ([changelog](https://www.tcpdump.org/tcpdump-changes.txt)) (PGP [signature](https://www.tcpdump.org/release/tcpdump-4.9.1.tar.gz.sig) and [key](https://www.tcpdump.org/release/signing-key.asc))
>
> **Version:** 4.9.0
> **Release Date:** January 18, 2017
> **Download:** [tcpdump-4.9.0.tar.gz](https://www.tcpdump.org/release/tcpdump-4.9.0.tar.gz) ([changelog](https://www.tcpdump.org/tcpdump-changes.txt)) (PGP [signature](https://www.tcpdump.org/release/tcpdump-4.9.0.tar.gz.sig) and [key](https://www.tcpdump.org/release/signing-key.asc))
>
> ### Libpcap
>
> **Version:** 1.8.1
> **Release Date:** October 25, 2016
> **Download:** [libpcap-1.8.1.tar.gz](https://www.tcpdump.org/release/libpcap-1.8.1.tar.gz) ([changelog](https://www.tcpdump.org/libpcap-changes.txt)) (PGP [signature](https://www.tcpdump.org/release/libpcap-1.8.1.tar.gz.sig) and [key](https://www.tcpdump.org/release/signing-key.asc))
>
> Version 1.8.0 was partially released in August 2016, but was withheld along with tcpdump 4.8.0.
>
> **Version:** 1.7.4
> **Release Date:** June 26, 2015
> **Download:** [libpcap-1.7.4.tar.gz](https://www.tcpdump.org/release/libpcap-1.7.4.tar.gz) ([changelog](https://www.tcpdump.org/libpcap-changes.txt)) (PGP [signature](https://www.tcpdump.org/release/libpcap-1.7.4.tar.gz.sig) and [key](https://www.tcpdump.org/release/signing-key.asc))

其中libpcap是抓包的库支持，向wireshark也是有这样类似的包。这两个解压缩后的文件最好在同一个目录下，可能会出现头文件找不到的情况



先编译libpcap：

```bash
export CC=mipsel-linux-gcc 	#指定编译器
./configure --host=mips-linux --with-pcap=linux
make
```



然后编译tcpdump(静态)：可以指定strip来去符号减少size

```bash
export ac_cv_linux_vers=2.6.22 	#路由器的Linux版本
export CFLAGS=-static
export CPPFLAGS=-static
export LDFLAGS=-static
./configure --host=mips-linux 
make
```



### 使用

[Tcpdump 示例教程 – 云原生实验室 - Kubernetes|Docker|Istio|Envoy|Hugo|Golang|云原生 (fuckcloudnative.io)](https://fuckcloudnative.io/posts/tcpdump-examples/)

这里我们主要是路由器抓包然后发送回主机，用wireshark进行解析

> 问题：多个网卡，怎么获取完整数据包



## netcat

编译：

```bash
wget http://sourceforge.net/projects/netcat/files/netcat/0.7.1/netcat-0.7.1.tar.gz/download -O netcat-0.7.1.tar.gz

cd netcat-0.7.1
export ac_cv_linux_vers=2.6.22 	#路由器的Linux版本
export CFLAGS=-static
export CPPFLAGS=-static
export LDFLAGS=-static
./configure --host=mips-linux 
make

cd src 
file ./netcat 
```



然后就可以进行传输