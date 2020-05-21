---
layout: post
title: pwntools使用
slug: nextrsa
date: 2018-03-28 17:00:36
status: publish
author: yuri
tags: 
  - pwn
  - pwntools
categories:
  - pwn
excerpt: Pwntools是一个CTF框架和利用开发库。用Python快速设计和开发，尽可能简化编写exploit过程。
---

# pwntools使用

## 安装

```bash
$ apt-get update
$ apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
$ pip install --upgrade pip
$ pip install --upgrade pwntools
```

如果想要在本地测试,可以这么做：

```bash
$ git clone https://github.com/Gallopsled/pwntools
$ pip install --upgrade --editable ./pwntools
```

使用时这样导入：

```python
from pwn import *
```

-------

## 连接

```python
r = = process('/bin/sh') #本地文件
r = remote('ftp.ubuntu.org',21) #远程，hostname + port

r.send(data)    #发送数据
r.sendline(data)    #发送数据 + '\n'

r.recv(numb=4096,timeout=default)   #接受指定字节数据,timeout指定超时
r.recvuntil(delims, drop=False) #接收到delims的pattern
r.recvline(keepends=True)   #接收到'\n'，keepends指定保留'\n'
r.recvall() #接收到EOF
r.recvrepeat(timeout=default)   #接收到EOF或timeout

r.interactive()   #与shell交互

r.close()   #断开连接
```

-------

## 数据

```bash
>>> import struct

>>> p32(0xdeadbeef) == struct.pack('I', 0xdeadbeef) #p32为打包,p64同理,小端序
True

>>> leet = '37130000'.decode('hex')
>>> u32('abcd') == struct.unpack('I', 'abcd')[0]     #u32为解包,u64同理,小端序
True

>>> u8('A') == 0x41
True
```

-------

## 设置目标架构和操作系统

全局设置context,可以包括字大小和端序。

```bash
>>> context.arch      = 'i386'
>>> context.os        = 'linux'
>>> context.endian    = 'little'
>>> context.word_size = 32

or

>>> context(arch='i386', os='linux', endian='little', word_size=32)
```
还有一个实用的可以显示调试信息：
```python
context.log_level = "debug"
```

-------

## ELF操作

```bash
>>> e = ELF('/bin/cat') #获取这个文件的句柄
>>> print hex(e.address) #基地址
0x400000
>>> print hex(e.symbols['write']) #函数地址
0x401680
>>> print hex(e.got['write']) #GOT表的地址
0x60b070
>>> print hex(e.plt['write']) #PLT表的地址
0x401680
```

-------

## 小工具

### 栈溢出找偏移

```bash
>>> print cyclic(20)    #生成20字节每4个字节(默认,可以给出参数如cyclic(20,n=8)指定)不随机的字符串
aaaabaaacaaadaaaeaaa
>>> # Assume EIP = 0x62616166 ('faab' which is pack(0x62616166))  at crash time
>>> print cyclic_find('faab')   #根据4个字符查找偏移,若n!=4必须指明n的参数
120
```

### 汇编与反汇编

```bash
>>> asm('mov eax, 0')   #汇编
'\xb8\x00\x00\x00\x00'
>>> disasm('\xb8\x0b\x00\x00\x00')  #反汇编
'   0:   b8 0b 00 00 00          mov    eax,0xb'
```

### Shellcode生成

shellcraft模块是shellcode的模块，包含一些生成shellcode的函数。其中的子模块声明架构，比如：
> * ARM架构: **shellcraft.arm**
> * AMD64架构: **shellcraft.amd64**
> * Intel 80386架构: **shellcraft.i386**
> * 通用: **shellcraft.common**

可以先声明框架直接汇编shellcraft.sh()：

```python
context(arch='i386', os='linux')
shellcode = asm(shellcraft.sh())
```
### DynELF

这里举了一个32位的例子：

```python
p = process('./pwnme')

# 声明一个只需要一个地址的函数，并在该地址至少泄漏（返回）一个字节
def leak(address):
    data = p.read(address, 4)
    log.debug("%#x => %s" % (address, (data or '').encode('hex')))
    return data

# 因为是举例，假设以下地址我们都知道。其中一个指向目标二进制文件里，另两个指向so库里
main   = 0xfeedf4ce
libc   = 0xdeadb000
system = 0xdeadbeef

#通过构造的leak函数和一个指向目标二进制文件里的指针，可以解析任何地址
#而且可以看到我们不需要这个目标二进制文件副本，直接解析
d = DynELF(leak, main)
assert d.lookup(None,     'libc') == libc
assert d.lookup('system', 'libc') == system

#但是，如果我们确实有目标二进制文件的副本，可以解析更快
d = DynELF(leak, main, elf=ELF('./pwnme'))
assert d.lookup(None,     'libc') == libc
assert d.lookup('system', 'libc') == system

#或者，我们可以解析另一个库中的符号，并给出一个指针
d = DynELF(leak, libc + 0x1234)
assert d.lookup('system')      == system
```

### fmtstr

`payload = fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')`

> * offset (int) – 第一个格式化偏移
> * writes (dict) – 字典，向哪个地址写入什么值 {addr: value, addr2: value2}
> * numbwritten (int) – 输出字符串已经写入字节数
> * write_size (str) – byte, short or int.即每次写一个字节、两个字节还是四个字节


### attach

该模块用于调用gdb调试
在python文件中直接设置断点，当运行到该位置之后就会断下

```python
import pwnlib
from pwn import *
p = process('./c')
pwnlib.gdb.attach(p)
```