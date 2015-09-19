USE_BRANDING := yes
IMPORT_BRANDING := yes
# makefile for xen component in build system
include $(B_BASE)/common.mk
include $(B_BASE)/rpmbuild.mk

# SHELL := /bin/bash
# SHELLOPTS := errexit:pipefail
# export SHELL SHELLOPTS

quiet ?= 0
ifneq ($(quiet),0)
  Q := @
else
  Q :=
endif

.PHONY: %var
%var:
	@echo "$* = $($*)"

# Pull repo name from $PWD rather than hard coding it
REPO_NAME := $(shell echo "$$PWD" | awk -F/ '{print $$3}')
RPM_BUILD_COOKIE := $(MY_OBJ_DIR)/.rpm_build_cookie
REPO_STAMP := $(call git_req,$(REPO_NAME))

CDFILES_COOKIE = $(MY_OBJ_DIR)/.cdfiles.cookie

$(eval $(shell $(call git_cset_number,$(REPO_NAME)))) # Defines CSET_NUMBER for us
XEN_VERSION := $(shell $(MAKE) -C $(call git_loc,$(REPO_NAME)) --no-print-directory xenversion)
XEN_RELEASE := $(PLATFORM_VERSION).$(CSET_NUMBER)

ifeq ($(BUILD_NUMBER),0x)
XEN_VENDORVERSION := -xs-local
else
XEN_VENDORVERSION := -xs$(shell echo $(BUILD_NUMBER) | tr -dc [:digit:])
endif

REPO_LOC := $(call git_loc,$(REPO_NAME))
BASE_CSET_STR := $(shell { git rev-parse --verify --short=12 qparent --git-dir=$(REPO_LOC)/.git; } )
PQ_CSET_STR   := $(shell { git rev-parse --verify --short=12 HEAD    --git-dir=$(REPO_LOC)/.git/patches/.git; } )

XEN_CHANGESET := "$(BASE_CSET_STR), pq $(PQ_CSET_STR)"

.PHONY: build
build: $(RPM_BUILD_COOKIE) $(BRANDING) $(MY_OUTPUT_DIR)/xen.inc \
       $(CDFILES_COOKIE)
	@ :

# # Xen packages

SOURCES := $(RPM_SOURCESDIR)/xen-$(XEN_VERSION).tar.bz2
SOURCES += $(RPM_SOURCESDIR)/sysconfig_kernel-xen
SOURCES += $(RPM_SOURCESDIR)/xl.conf
SOURCES += $(RPM_SOURCESDIR)/logrotate-xen-tools
SOURCES += $(RPM_SPECSDIR)/xen.spec
SOURCES += $(RPM_SOURCESDIR)/xen-development.patch

XEN_HG_EXCLUDE := -X mk

$(RPM_SOURCESDIR)/xen-$(XEN_VERSION).tar.bz2: $(RPM_SOURCESDIR)/.dirstamp
	{ set -e; set -o pipefail; \
	cd $(REPO_LOC); \
	git archive --format=tar --prefix=xen-$(XEN_VERSION)/ HEAD | bzip2 -9 > $@.tmp; \
	mv -f $@.tmp $@; \
	}

$(RPM_SOURCESDIR)/%: %
	cp $^ $@

$(RPM_SOURCESDIR)/xen-development.patch: $(RPM_SOURCESDIR)/.dirstamp
	{ set -e; set -o pipefail; \
	cd $(REPO_LOC); \
	git diff HEAD > $@.tmp; \
	mv -f $@.tmp $@; \
	}

$(RPM_SPECSDIR)/xen.spec: xen.spec.in $(RPM_SPECSDIR)/.dirstamp Makefile
	{ set -e; set -o pipefail; \
	sed -e s/@XEN_VERSION@/$(XEN_VERSION)/g \
	    -e s/@XEN_RELEASE@/$(XEN_RELEASE)/g \
	    -e s/@XEN_CHANGESET@/$(XEN_CHANGESET)/g \
	    -e s/@XEN_VENDORVERSION@/$(XEN_VENDORVERSION)/g \
	< $< > $@.tmp; \
	mv -f $@.tmp $@; \
	}

$(RPM_BUILD_COOKIE): $(RPM_DIRECTORIES) $(SOURCES)
	$(RPMBUILD) --target $(DOMAIN0_ARCH_OPTIMIZED) -ba $(RPM_SPECSDIR)/xen.spec
	$(Q)touch $@

# # Files for CD
HYPERVISOR_OUTPUT_RPM := xen-hypervisor-$(XEN_VERSION)-$(XEN_RELEASE).$(DOMAIN0_ARCH_OPTIMIZED).rpm

$(CDFILES_COOKIE): $(RPM_BUILD_COOKIE) $(MY_MAIN_CDFILES)/.dirstamp
	rpm2cpio $(MY_OUTPUT_DIR)/RPMS/$(DOMAIN0_ARCH_OPTIMIZED)/$(HYPERVISOR_OUTPUT_RPM) | \
		( cd $(MY_MAIN_CDFILES) ; cpio --extract --make-directories --unconditional ./boot/xen-$(XEN_VERSION)$(XEN_VENDORVERSION)-d.gz )
	mv $(MY_MAIN_CDFILES)/boot/xen-$(XEN_VERSION)$(XEN_VENDORVERSION)-d.gz $(MY_MAIN_CDFILES)/boot/xen.gz
	touch $@

# # SOURCES, BRANDING etc

.PHONY: $(MY_OUTPUT_DIR)/xen.inc
$(MY_OUTPUT_DIR)/xen.inc: $(MY_OUTPUT_DIRSTAMP)
	{ set -e; set -o pipefail; \
	$(Q){ echo XEN_PKG_NAME := xen; \
	  echo XEN_PKG_VERSION := $(XEN_VERSION)-$(XEN_RELEASE); \
	  echo XEN_PKG_ARCH := $(DOMAIN0_ARCH_OPTIMIZED); \
	  echo XEN_PKG_FILE := RPMS/$(DOMAIN0_ARCH_OPTIMIZED)/$(OUTPUT_RPM); \
	  echo XEN_VERSION := $(XEN_VERSION); \
	  echo XEN_RELEASE := $(XEN_RELEASE); \
	} > $@.tmp; \
	mv -f $@.tmp $@; \
	}

.PHONY: $(BRANDING)
$(BRANDING): $(MY_OUTPUT_DIR)/.dirstamp
	{ set -e; set -o pipefail; \
	$(Q)echo "XEN_VERSION := $(XEN_VERSION)" > $@.tmp; \
	mv -f $@.tmp $@; \
	}

.PHONY: clean
clean:
	rm -f $(RPM_BUILD_COOKIE)
	rm -f $(SOURCES)
	rm -f $(SOURCES:%=%.tmp)
	rm -f $(MY_OUTPUT_DIR)/xen.inc
