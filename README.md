# 校园网认证程序

这个程序用于校园网的 802.1X EAP-MD5 认证，目前支持 华中科技大学 / Linux系统，需要在 Python 3.5+ 下运行。

这个程序处于第二阶段的开发状态，正在通过软件逆向模仿 rjsupplicant 的认证过程。

## 用法

```bash
$ sudo python main.py -n enp3s0 -u GloveAn -p HelloWorld
```

程序需要三个输入，分别是网卡名称、用户名和密码，对应的参数为 -n / -u / -p 。由于使用到了 raw socket，所以需要root权限。**注意**：输入的密码会被保存在 history 中。

## 致谢

[radare2](http://radare.org/r/)

[gdb](https://www.gnu.org/software/gdb/)

[MentoHust origin](https://code.google.com/archive/p/mentohust/)( + issue #177)

[MentoHust v4](https://github.com/hyrathb/mentohust)

[YaH3C](https://github.com/humiaozuzu/YaH3C)

---

![Creative Common](https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png)
