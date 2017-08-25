# 校园网认证程序

这个是我自己写的第三方校园网认证客户端，用于华科的校园网认证。认证协议主要通过软件逆向分析得到，同时也参考了前辈们的一些工作，并修复了其中的bug。

从高三接触到patch和keygen的时候开始，我就有了当黑客的梦想。进入大学之后，学校不让共享校园网帐号，不让开wifi热点，于是我就有了就拿校园网下手，实现黑客梦的想法。

## 用法

项目主体是Python写的，下载下来就可以用。

```bash
$ sudo python main.py -n enp3s0 -u GloveAn -p HelloWorld
```

程序需要三个输入，分别是网卡名称、用户名和密码，对应的参数为 -n / -u / -p 。由于使用到了raw socket，所以需要root权限。**注意**：输入的密码会被保存在history中。

程序中有一个模块用于生成客户端的hash值校验，这个模块是用C语言写的。要使用这个模块，需要先用./packets/ruijie/setup.py对其进行编译，然后将编译好的.so文件移动到./packets/目录下。不过因为华科没有开启客户端的hash值校验，所以可以不使用这个模块。

到目前为止程序中还没有用到依赖操作系统的东西，所以linux、windows和mac都能用。当然因为windows下没有Python环境，对命令行的支持不好，所以用起来会麻烦些。

## 致谢

我首次了解校园网的认证过程，是通过[MentoHust](https://code.google.com/archive/p/mentohust/)这个项目。不过因为校园网的升级，这个项目不再可用了。后来有前辈研究了升级后的官方客户端，keygen了里面的hash函数，开发了[MentoHust v3](https://github.com/hyrathb/mentohust)版本。在keygen成果的帮助下，我的工作量减少了很多。客户端中用到的hash函数改编自[libTomcrypt](http://www.libtom.net/LibTomCrypt/)；raw socket的用法是从[YaH3C](https://github.com/humiaozuzu/YaH3C)这个项目中学到的。

项目中的软件逆向部分是通过[radare2](http://radare.org/r/)和[gdb](https://www.gnu.org/software/gdb/)完成的，一个负责静态分析，一个负责动态调试。客户端由[Python 3](https://www.python.org/)和[C语言](https://gcc.gnu.org/)编写，在[linux](https://www.linux.org/)下开发。

---

![Creative Common](https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png)
