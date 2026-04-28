#!/system/bin/sh
MODDIR=${0%/*}
for mod in "$MODDIR"/rekernel-*.ko; do
    if [ -f "$mod" ]; then
        if insmod "$mod" >/dev/null 2>&1; then
            break
        fi
    fi
done
