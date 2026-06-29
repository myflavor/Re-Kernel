# Develop

Userspace integration layer for [ReKernel-X](https://github.com/Sakion-Team/ReKernel-X).

ReKernel-X exposes a **Generic Netlink** server in the kernel module. Userspace
tombstone / crash-capture apps connect to it to receive binder, signal, and
network events that the kernel hooks. This folder ships the Android client
packaged as an **AAR** so app developers don't have to speak raw netlink.

```
┌──────────────┐   genl "rekernel_x" family   ┌──────────────────┐
│  Your App    │ ──── REKERNEL_A_UID cmd ──▶│  ReKernel-X LKM   │
│  (Java + JNI)│ ◀── events mcast group ───│  (LKM-Source/)   │
└──────────────┘                            └──────────────────┘
```

## Contents

| Path | Purpose |
|---|---|
| `aar/` | Android AAR project — the client library |
| `aar/rekernelx/src/main/cpp/rekernel_jni.cpp` | C++ netlink client + JNI bridge |
| `aar/rekernelx/src/main/java/cn/myflv/kernel/` | Java API (`ReKernelX`, `ReKernelXCallback`) |
| `aar/README.md` | Build instructions + full usage example |

See [`aar/README.md`](aar/README.md) for build prerequisites, ABI-compatibility
notes, and a complete Java usage snippet.

## Protocol overview

The client resolves the `"rekernel_x"` genl family by name via
`CTRL_CMD_GETFAMILY`, joins the `"events"` multicast group, and receives binary
`struct rekernelx_event` messages — a tagged union read by fixed offset, **not**
a formatted string. It sends `MONITOR_NET` / `DEL_MONITOR_NET` commands carrying
a uid to be monitored.

The on-wire ABI is defined in [`../LKM-Source/rekernelx.h`](../LKM-Source/rekernelx.h)
and mirrored byte-for-byte in the JNI source. `static_assert(sizeof(rekernelx_event) == 172)`
catches drift at compile time. **If the kernel ABI changes, update both
`rekernelx.h` and `rekernel_jni.cpp` together.**

## Quick start

```java
import cn.myflv.kernel.ReKernelX;
import cn.myflv.kernel.ReKernelXCallback;

boolean ok = ReKernelX.startListening(new ReKernelXCallback() {
    @Override public void disconnected() { /* unexpected drop; not fired on stopListening() */ }
    @Override public void binder(int binderType, int oneway, int from, int fromPid, int target, int targetPid, String rpc, int code) {}
    @Override public void signal(int signal, int killer, int killerPid, int dst, int dstPid) {}
    @Override public void network(int proto, int target, int dataLen) {}
});
if (ok) ReKernelX.addMonitorNet(uid);
// ...
ReKernelX.stopListening();
```

Requirements: a rooted device with the ReKernel-X kernel module loaded
(kernel ≥ 5.10; see the root README).
