#!/bin/bash

./configure --prefix=/usr \
            --libdir=/usr/lib64 \
            --libexecdir=/usr/libexec \
            --disable-qemu-traditional \
            --disable-seabios \
            --disable-stubdom \
            --disable-xsmpolicy \
            --enable-rombios \
            --enable-systemd \
            --with-xenstored=oxenstored \
            --with-system-qemu=/usr/lib64/xen/bin/qemu-system-i386 \
            --with-system-ipxe=/usr/share/ipxe/ipxe.bin \
            --with-system-ovmf=/usr/share/edk2/OVMF.fd

for CFG in debug release
do
    make -C xen/ KCONFIG_CONFIG=../buildconfigs/config-$CFG olddefconfig
done
