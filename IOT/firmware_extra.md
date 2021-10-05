# 固件提取思路



## UART

UART进行调试的时候不一定能进入Linux shell，那么可以看看Uboot或CFE 命令行（shell）

+ CFE：连接后`ctrl + c`
+ uboot：连接后回车

然后使用`?/help`来尝试获取当前shell的命令表，如果存在**读内存的命令**就有办法了

### Cisco RV110 

```bash
CFE> ^C
CFE> help 
CMD: [help]
Available commands:

upgrade             Upgrade Firmware
et                  Broadcom Ethernet utility.
modify              Modify flash data.
nvram               NVRAM utility.
reboot              Reboot.
flash               Update a flash memory device
memtest             Test memory.
f                   Fill contents of memory.
e                   Modify contents of memory.
d                   Dump memory.
u                   Disassemble instructions.
batch               Load a batch file into memory and execute it
go                  Verify and boot OS image.
boot                Load an executable file into memory and execute it
load                Load an executable file into memory without executing it
save                Save a region of memory to a remote file via TFTP
ping                Ping a remote IP host.
arp                 Display or modify the ARP Table
ifconfig            Configure the Ethernet interface
show clocks         Show current values of the clocks.
show heap           Display information about CFE's heap
show memory         Display the system physical memory map.
show devices        Display information about the installed devices.
unsetenv            Delete an environment variable.
printenv            Display the environment variables
setenv              Set an environment variable.
gpio                Get/Set GPIO
help                Obtain help for CFE commands
```

使用的是CFE作为bootloader，内置的命令`d                   Dump memory.`来读取flash。其读取输出特点：

```bash
CMD: [d]
80000000: 3C1B8842 041E4000 0F0B1110 001B9702  B..<.@..........
80000010: 021AD080 0B6FD825 001A2100 8F7B0304  ....%.o..!....{.
80000020: 080AC442 2B5A0FE8 076A5A21 0F7A0009  B.....Z+!Zj...z.
```

接下来从该bootloader初始化的输出信息中找到固件位置的信息，不是很远就在开头的样子：

```bash
Check CRC of image1
  Len:     0xA38000     (10715136)      (0xBC040000)
  Offset0: 0x1C         (28)            (0xBC04001C)
  Offset1: 0x173BB0     (1522608)       (0xBC1B3BB0)
  Offset2: 0x0  (0)     (0xBC040000)
  Header CRC:    0x4B3F4843
  Calculate CRC: 0x4B3F4843
Image 1 is OK
Try to load image 1.
CMD: [boot -raw -z -addr=0x80001000 -max=0x9ff000 flash0.os:]
Loader:raw Filesys:raw Dev:flash0.os File: Options:(null)
Loading: ...... 4299308 bytes read

### Start=1824020155 E=-1940415061 Delta=530532080 ###
Entry at 0x80001000
Closing network.
Starting program at 0x80001000
Linux version 2.6.22 (root@localhost.localdomain) (gcc version 4.2.3) #1 Wed Feb 24 16:16:48 CST 2016
CPU revision is: 00019749
Found an ST compatible serial flash with 256 64KB blocks; total size 16MB
Determined physical RAM map:
 memory: 04000000 @ 00000000 (usable)
```

+ check `CRC`
+ 几个offset
+ 然后load image
+ start linux

这里就很明显了，所以从`0xBC040000`开始提取`0xA38000`个字节。没有编程器就写个脚本(读取好几十分钟~)：

```python
#!/usr/bin/env python3
import argparse
import struct
import re

parser = argparse.ArgumentParser(description="Use for tranmite minicom.cap to bin")

parser.add_argument('-f', '--file', type=str, help="target **.cap file path")
parser.add_argument('-s', '--start', type=str, help="target start addr")
parser.add_argument('-e', '--end', type=str, help="target end addr")

args = parser.parse_args()

if int(args.start, 16) > int(args.end, 16):
    print("start > end!")
    exit(-1)

binfile = open(args.file + '.bin', "bw+")
mode = r'([0-9A-Z]{8}): ([0-9A-Z]{16}) ([0-9A-Z]{16}) .*'
with open(args.file) as f:
    for line in f:
        mat = re.match(mode, line)  
        if mat and (int(mat.group(1), 16)>=int(args.start, 16)) and (int(mat.group(1), 16)<int(args.end, 16)):
            binfile.write(struct.pack('<Q', int(mat.group(2), 16)))
            binfile.write(struct.pack('<Q', int(mat.group(3), 16)))
        else:
            continue
print("Done!")
```

Result：

```bash
iot@attifyos ~> binwalk -Mv ./minicom.cap.bin 

Scan Time:     2021-10-05 01:15:48
Target File:   /home/iot/minicom.cap.bin
MD5 Checksum:  0247df1745e607a0fb9568a5bbed91db
Signatures:    396

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             TRX firmware header, little endian, image size: 10715136 bytes, CRC32: 0x4B3F4843, flags: 0x0, version: 1, header size: 28 bytes, loader offset: 0x1C, linux kernel offset: 0x173BB0, rootfs offset: 0x0
28            0x1C            LZMA compressed data, properties: 0x5D, dictionary size: 65536 bytes, uncompressed size: 4299308 bytes
1522384       0x173AD0        Squashfs filesystem, little endian, non-standard signature, version 3.0, size: 9188819 bytes, 1072 inodes, blocksize: 65536 bytes, created: 2016-02-24 08:40:47
```

