# ReKernelX AAR

JNI implementation of the ReKernel-X Generic Netlink client, packaged as an Android AAR.

## Build Prerequisites

- JDK 17
- Android SDK with: `platforms;android-34`, `build-tools;34.0.0`, `ndk;27.0.12077973`, `cmake;3.22.1`
- Gradle wrapper is included; no separate Gradle installation needed.

```bash
export JAVA_HOME=/path/to/jdk17
export ANDROID_HOME=/path/to/Android/Sdk
./gradlew :rekernel_x:assembleRelease
```

Output: `rekernel/build/outputs/aar/rekernel-release.aar`

## ABI Compatibility

The wire protocol uses nested Netlink attributes (NLA), mirroring the kernel's
`nla_put_*` / `nla_get_*` helpers. Attribute IDs and genl commands in
`rekernel_x_jni.cpp` must match `LKM-Source/rekernel_x.h`. NLA read/write
helpers live in `rekernel_x_nla.h`.

If the kernel ABI changes, update both `rekernel_x.h` and `rekernel_x_jni.cpp`
in tandem (attribute IDs, commands, event types).

## Threading model

The user drives the connection lifecycle from Java; the native side spawns no
thread of its own.

- `setCallback(cb)` — install (or replace, or clear with `null`) the callback.
- `connect()` — non-blocking: builds the socket, resolves the genl family,
  joins the multicast group. Returns `true` on success.
- `pollEvent()` — BLOCKS the calling thread, dispatching events to the callback
  until the connection drops. Returning means "disconnected".
- `disconnect()` — call from ANOTHER thread to close the socket, which wakes
  `pollEvent()` out of its blocking recv.

Constraints:

- The callback runs on the thread blocked in `pollEvent()`; its implementation
  MUST NOT call `connect()` / `disconnect()` / `pollEvent()` — doing so would
  self-deadlock.
- `disconnect()` MUST be called from a thread other than the one in `pollEvent()`.
- `addMonitorNet` / `delMonitorNet` may be called from any thread while polling.

## Usage

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

## ProGuard / R8

Consumer ProGuard rules are bundled in the AAR (`consumer-rules.pro`).
They automatically keep `ReKernelX` (native methods) and `ReKernelXCallback`
(interface + implementations) when the host app enables R8 minification.
