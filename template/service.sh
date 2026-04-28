#!/system/bin/sh
MODDIR=${0%/*}

if [ -f "$MODDIR"/.boot ]; then
    rm "$MODDIR"/.boot
    exit 0
fi

touch "$MODDIR"/.boot
sync
sleep 1

for mod in "$MODDIR"/rekernel-*.ko; do
    if [ -f "$mod" ]; then
        if insmod "$mod" >/dev/null 2>&1; then
            break
        fi
    fi
done

rm "$MODDIR"/.boot
