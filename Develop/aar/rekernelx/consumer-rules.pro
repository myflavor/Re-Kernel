# ReKernelX AAR consumer ProGuard/R8 rules.
# These rules are automatically applied to consuming projects when R8 is enabled.

# Keep the ReKernelX class and its native methods.
# Renaming or stripping native methods would cause UnsatisfiedLinkError at runtime.
-keep class cn.myflv.kernel.ReKernelX {
    native <methods>;
    public static *;
}

# Keep the ReKernelXCallback interface and all its method signatures,
# so JNI GetMethodID descriptors always match.
-keep interface cn.myflv.kernel.ReKernelXCallback {
    *;
}

# Keep any class that implements ReKernelXCallback (the host app's implementations).
-keep class * implements cn.myflv.kernel.ReKernelXCallback {
    *;
}
