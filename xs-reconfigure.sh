#!/bin/bash

./configure --prefix=/usr \
            --libdir=/usr/lib64 \
            --libexecdir=/usr/libexec \
            --disable-qemu-traditional \
            --disable-seabios \
            --disable-stubdom \
            --disable-xsmpolicy \
            --disable-pvshim \
            --enable-rombios \
            --enable-systemd \
            --with-xenstored=oxenstored \
            --with-system-qemu=/usr/lib64/xen/bin/qemu-system-i386 \
            --with-system-ipxe=/usr/share/ipxe/ipxe.bin \
            --with-system-ovmf=/usr/share/edk2/OVMF.fd

shopt -s extglob

# Pick all config-$foo but skip *.old
for CFG in buildconfigs/config-*!(.old)
do
    make -C xen/ KCONFIG_CONFIG=../$CFG olddefconfig
done
