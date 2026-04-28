#!/system/bin/sh
MODDIR=${0%/*}

if [ -f "$MODDIR"/.boot ]; then
    touch "$MODDIR"/disable
    rm "$MODDIR"/.boot
else
    touch "$MODDIR"/.boot
fi
