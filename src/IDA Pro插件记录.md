---
layout: post
title: IDA Pro 插件记录
slug: IdaPlug
date: 2020-07-08 22:18
status: publish
author: yuri
tags: 
  - reverse
  - ida
categories:
  - reverse
excerpt: 记录使用的IDA Pro插件。
---


# IDA Pro 插件记录

> `version: 7.5`



## [BinaryAI](https://github.com/binaryai/sdk)

```bash
pip install --upgrade binaryai
# then you can add the binaryai plugin into $IDAUSR
binaryai install_ida_plugin
```



## [flare-emu](https://github.com/fireeye/flare-emu)

```python
import flare_emu

def decrypt(argv):
    myEH = flare_emu.EmuHelper()
    myEH.emulateRange(myEH.analysisHelper.getNameAddr("decryptString"), registers = {"arg1":argv[0], "arg2":argv[1], 
                           "arg3":argv[2], "arg4":argv[3]})
    return myEH.getEmuString(argv[0])
    
def iterateCallback(eh, address, argv, userData):
    s = decrypt(argv)
    print("%s: %s" % (eh.hexString(address), s))
    eh.analysisHelper.setComment(address, s, False)
    
if __name__ == '__main__':   
    eh = flare_emu.EmuHelper()
    eh.iterate(eh.analysisHelper.getNameAddr("decryptString"), iterateCallback)
```



## [x64dbgida](https://github.com/x64dbg/x64dbgida)

官方插件



## [VT-IDA Plugin](https://github.com/VirusTotal/vt-ida-plugin)

官方插件，还在开发，极其不稳定



## [LazyIDA](https://github.com/L4ys/LazyIDA)

shortcuts:

- Disasm Window:
  - `w`: Copy address of current line into clipboard
- Hex-rays Window:
  - `w`: Copy address of current item into clipboard
  - `c`: Copy name of current item into clipboard
  - `v`: Remove return type of current item



## [Ponce](https://github.com/illera88/Ponce)

符号执行+污点传播



## [Karta](https://github.com/CheckPointSW/Karta)

* [Docs](https://karta.readthedocs.io/en/latest/)

