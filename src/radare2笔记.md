---
layout: post
title: Radare2笔记
slug: Radare2Note
date: 2020-07-05 17:20
status: publish
author: yuri
tags: 
  - reverse
  - radare2
categories:
  - reverse
excerpt: Radare2笔记（不断更新）。
---

# Radare2笔记

## radare2

| Command     | Description                          |
| ----------- | ------------------------------------ |
| aaaa        | Fully analyze the binary             |
| afl         | List all the functions in the binary |
| afv         | Analyze the functions variables      |
| ii          | List imports                         |
| iI          | Information about the binary         |
| iz          | List strings in the binary           |
| sf function | Seek to a function                   |
| pdb         | Print disassembly of the basic block |
| pdf         | Print disassembly of the function    |

## rahash2

`rahash2 -L`: 列举支持的算法

常见用法：
* 字符串哈希：`rahash2 -a md5 -s admin`
* 文件哈希：`rahash2 -a md5 bin`
