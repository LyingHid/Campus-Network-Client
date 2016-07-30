# 校园网认证程序

这个程序用于校园网的 802.1X 认证。
程序目前支持 华中科技大学 / Linux系统，需要在 Python 3.5 下运行。

**注意**：目前这个程序还处于非常早期的开发状态，各方面都需要继续完善，也存在安全问题。

## 用法

```bash
sudo python main.py -i enp3s0 -u USERNAME -p PASSWORD
```

程序需要三个输入，分别是网卡名称、用户名和密码，对应的参数为 -i / -u / -p 。


## 作者

Glove An


## 许可

![Creative Common](https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png)

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.


## 致谢

[MentoHust](https://code.google.com/archive/p/mentohust/) (照着这个项目的源码结合抓包改的)
