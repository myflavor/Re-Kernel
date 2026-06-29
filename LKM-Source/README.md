# LKM Source

ReKernel-X Loadable Kernel Module source code. Supports GKI kernels from Android 12 (5.10) through Android 16 (6.12).

## Source Files

| File | Description |
|---|---|
| `rekernelx_main.c` | Module entry/exit, init/exit glue |
| `rekernelx_genl.c` | Generic Netlink transport |
| `rekernelx_binder.c` | Binder transaction hooks |
| `rekernelx_binder_kp.c` | Binder kprobe hooks |
| `rekernelx_signal.c` | Signal hooks |
| `rekernelx_netfilter.c` | Netfilter hooks |
| `rekernelx_netuid.c` | Network monitor UID hashmap |
| `rekernelx_frozen.c` | Task frozen-state predicate |
| `rekernelx.h` | Shared header, ABI definitions |
| `Makefile` | Kernel module build rules |
| `Kconfig` | Kernel config option |

## Building

Build via the `ddk-lkm.yml` reusable workflow, or manually inside a DDK container:

```sh
# Copy sources into kernel tree
cp *.c *.h /opt/ddk/src/<KMI>/drivers/android/
cat Makefile >> /opt/ddk/src/<KMI>/drivers/android/Makefile

# Build
cd /opt/ddk/src/<KMI>
make -C /opt/ddk/kdir/<KMI> \
    M=/opt/ddk/src/<KMI>/drivers/android \
    CONFIG_REKERNEL_X=m \
    CC="clang" \
    REKERNELX_VERSION="v1.0" \
    modules
```

## Version

The module version is defined in `rekernelx.h`:

```c
#ifndef REKERNELX_VERSION
#define REKERNELX_VERSION "snapshot"
#endif
```

Pass `REKERNELX_VERSION` as a make variable to override the default `snapshot` value. The version is printed in `dmesg` on module load.
