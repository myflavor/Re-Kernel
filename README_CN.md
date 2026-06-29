# ReKernel-X
[![C](https://img.shields.io/badge/language-C-%23f34b7d.svg?style=plastic)](https://en.wikipedia.org/wiki/C_(programming_language)) 
[![Android](https://img.shields.io/badge/platform-Android-0078d7.svg?style=plastic)](https://en.wikipedia.org/wiki/Android_(operating_system)) 
[![AArch64](https://img.shields.io/badge/arch-AArch64-red.svg?style=plastic)](https://en.wikipedia.org/wiki/AArch64)

使墓碑用户获得更好的使用体验。

## 许可
此项目正在使用 [GPL 许可证](LICENSE), 如果需要对此项目进行修改或二次分发，请同样保持开源。

## 下载
从 [GitHub Releases](https://github.com/myflavor/ReKernel-X/releases) 下载最新版本。

## 特殊准备
你的设备需要通过 Magisk (v20.4+) 获取 Root 权限，内核版本需要 >= 5.10。

### 方法一: Magisk 模块（推荐）
通过 Magisk 刷入 Re:Kernel 模块，开机后自动挂载。

### 方法二: 手动挂载
从 Magisk 模块中提取 `rekernel_x.ko`，放入 `/data/`，然后执行：
```sh
insmod rekernel_x.ko
```
> 重启后失效。建议先用此方法验证兼容性，再刷入 Magisk 模块。

## 为墓碑接入 Re:Kernel
Re:Kernel 通过 Generic Netlink 对外开放接口，详情请查看 [Develop](Develop) 文件夹。

## Q / A
Q: 这个模块会泄露 Root 吗？

A: 不会，内核模块是无法被检测到的。
