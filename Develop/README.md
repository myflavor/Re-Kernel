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
| `aar/rekernel_x/src/main/cpp/rekernel_x_jni.cpp` | C++ netlink client + JNI bridge |
| `aar/rekernel_x/src/main/cpp/rekernel_x_nla.h` | NLA read/write helpers (shared) |
| `aar/rekernel_x/src/main/java/cn/myflv/kernel/` | Java API (`ReKernelX`, `ReKernelXCallback`) |
| `aar/README.md` | Build instructions + full usage example |

See [`aar/README.md`](aar/README.md) for build prerequisites, ABI-compatibility
notes, and a complete Java usage snippet.

## Protocol overview

The client resolves the `"rekernel_x"` genl family by name via
`CTRL_CMD_GETFAMILY`, joins the `"events"` multicast group, and receives events
serialised as **nested Netlink attributes** (NLA) — not a flat struct or a
formatted string. It sends `ADD_MONITOR_NET` / `DEL_MONITOR_NET` commands
carrying a uid to be monitored.

The on-wire ABI (attribute IDs, genl commands, event types) is defined in
[`../LKM-Source/rekernel_x.h`](../LKM-Source/rekernel_x.h) and mirrored in the
JNI source. **If the kernel ABI changes, update both `rekernel_x.h` and
`rekernel_x_jni.cpp` together.**

## Quick start

```java
import cn.myflv.kernel.ReKernelX;
import cn.myflv.kernel.ReKernelXCallback;

import static cn.myflv.kernel.ReKernelXCallback.*;

new Thread(() -> {

    if (ReKernelX.connect()) {


        Log.i("ReKernel-X", "connected");

        ReKernelX.setCallback(new ReKernelXCallback() {
            @Override
            public void binder(int binderType, int oneway, int fromUid, int fromPid, int targetUid, int targetPid, String rpcName, int code) {
                Log.i("ReKernel-X", String.format("transaction = %s", binderType == BINDER_TRANSACTION));
                Log.i("ReKernel-X", String.format("replay = %s", binderType == BINDER_REPLY));
                Log.i("ReKernel-X", String.format("freeBufferFull = %s", binderType == BINDER_FREE_BUFFER_FULL));
            }

            @Override
            public void signal(int signal, int killerUid, int killerPid, int dstUid, int dstPid) {

            }

            @Override
            public void network(int proto, int targetUid, int dataLen) {
                Log.i("ReKernel-X", String.format("ipv4 = %s", proto == PROTO_IPV4));
                Log.i("ReKernel-X", String.format("ipv6 = %s", proto == PROTO_IPV6));
            }
        });

        ReKernelX.pollEvent();

        Log.i("ReKernel-X", "disconnected");

    }


}).start();

ReKernelX.addMonitorNet(1000);

ReKernelX.delMonitorNet(1000);

ReKernelX.disconnect();
```

Requirements: a rooted device with the ReKernel-X kernel module loaded
(kernel ≥ 5.10; see the root README).
