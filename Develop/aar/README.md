# ReKernelX AAR

JNI implementation of the ReKernel-X Generic Netlink client, packaged as an Android AAR.

## Build Prerequisites

- JDK 17
- Android SDK with: `platforms;android-34`, `build-tools;34.0.0`, `ndk;27.0.12077973`, `cmake;3.22.1`
- Gradle wrapper is included; no separate Gradle installation needed.

```bash
export JAVA_HOME=/path/to/jdk17
export ANDROID_HOME=/path/to/Android/Sdk
./gradlew :rekernelx:assembleRelease
```

Output: `rekernel/build/outputs/aar/rekernel-release.aar`

## ABI Compatibility

The JNI structures mirror `LKM-Source/rekernelx.h` byte-for-byte (tagged union, `#pragma pack(1)`).
`static_assert(sizeof(rekernelx_event)==172)` enforces this at compile time.

If the kernel ABI changes, update both `rekernelx.h` and `rekernel_jni.cpp` in tandem.

## Usage

```java
import cn.myflv.kernel.ReKernelX;
import cn.myflv.kernel.ReKernelXCallback;

boolean ok = ReKernelX.startListening(new ReKernelXCallback() {
    @Override public void disconnected() { /* unexpected drop; not fired on stopListening() */ }
    @Override public void binder(int binderType, int oneway, int from, int fromUid, int target, int targetUid, String rpcName, int code) { /* ... */ }
    @Override public void signal(int signal, int killer, int killerPid, int dst, int dstPid) { /* ... */ }
    @Override public void network(int proto, int target, int dataLen) { /* ... */ }
});
if (ok) {
    ReKernelX.addMonitorNet(uid);
}
// ...
ReKernelX.stopListening();
```

## ProGuard / R8

Consumer ProGuard rules are bundled in the AAR (`consumer-rules.pro`).
They automatically keep `ReKernelX` (native methods) and `ReKernelXCallback` (interface + implementations) when the host app enables R8 minification.
