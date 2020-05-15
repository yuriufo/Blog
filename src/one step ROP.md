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
