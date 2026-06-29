# ReKernel-X
[![C](https://img.shields.io/badge/language-C-%23f34b7d.svg?style=plastic)](https://en.wikipedia.org/wiki/C_(programming_language)) 
[![Android](https://img.shields.io/badge/platform-Android-0078d7.svg?style=plastic)](https://en.wikipedia.org/wiki/Android_(operating_system)) 

Make tombstone users get a better experience. ([简体中文](README_CN.md))

## License
This project is using a [GPL License](LICENSE), If you need to modify or redistribute this project, please also keep it open source.

## Downloading
Download the latest release from [GitHub Releases](https://github.com/myflavor/ReKernel-X/releases).

## Prerequisites
Your device must be rooted with Magisk (v20.4+). Kernel version >= 5.10 is required.

### Method 1: Magisk Module (Recommended)
Flash the Re:Kernel Magisk module via Magisk. It will automatically load after each boot.

### Method 2: Manual Mount
Extract `rekernel_x.ko` from the Magisk module, place it in `/data/local/tmp/`, then run:
```sh
insmod rekernel_x.ko
```
> The module will be unloaded after reboot. Use this method to verify compatibility before flashing the Magisk module.

## Connecting the tombstone to Re:Kernel
Re:Kernel exposes a Generic Netlink server for tombstone integration. See the [Develop](Develop) folder for details.

## Q / A
Q: Will this module leak Root?

A: No, the kernel module cannot be detected.
