# Xen system configuration
# ========================
#
# Xen uses a set of variables for system configuration and at build time,
# because of this these variables are defined on one master input source file
# and is generated after running ./configure. The master source is located
# on the xen source tree at under config/Paths.mk.in and it is used to
# generate shell or header files by the build system upon demand through the
# use of the helper makefile helper buildmakevars2file().
#
# For more documentation you can refer to the wiki:
#
# https://wiki.xen.org/wiki/Category:Host_Configuration#System_wide_xen_configuration

PACKAGE_TARNAME          := xen
prefix                   := /usr
bindir                   := /usr/bin
sbindir                  := /usr/sbin
libdir                   := /usr/lib64
libexecdir               := /usr/libexec
datarootdir              := ${prefix}/share
mandir                   := ${datarootdir}/man
docdir                   := ${datarootdir}/doc/${PACKAGE_TARNAME}
dvidir                   := ${docdir}
htmldir                  := ${docdir}
pdfdir                   := ${docdir}
psdir                    := ${docdir}
includedir               := ${prefix}/include
localstatedir            := /var
sysconfdir               := /etc

LIBEXEC                  := /usr/libexec/xen
LIBEXEC_BIN              := /usr/libexec/xen/bin
LIBEXEC_LIB              := /usr/libexec/xen/lib
LIBEXEC_INC              := /usr/libexec/xen/include

SHAREDIR                 := /usr/share
MAN1DIR                  := $(mandir)/man1
MAN8DIR                  := $(mandir)/man8

XEN_RUN_DIR              := /var/run/xen
XEN_LOG_DIR              := /var/log/xen
XEN_LIB_DIR              := /var/lib/xen
XEN_RUN_STORED           := /var/run/xenstored

CONFIG_DIR               := /etc
INITD_DIR                := /etc/rc.d/init.d
CONFIG_LEAF_DIR          := sysconfig
BASH_COMPLETION_DIR      := $(CONFIG_DIR)/bash_completion.d
XEN_LOCK_DIR             := /var/lock
XEN_PAGING_DIR           := /var/lib/xen/xenpaging
XEN_DUMP_DIR             := /var/lib/xen/dump
DEBUG_DIR                := /usr/lib/debug

XENFIRMWAREDIR           := /usr/libexec/xen/boot

XEN_CONFIG_DIR           := /etc/xen
XEN_SCRIPT_DIR           := /etc/xen/scripts

PKG_INSTALLDIR           := ${libdir}/pkgconfig
