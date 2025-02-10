/* SPDX-License-Identifier: MIT */
/**
 * pv-iommu.h
 *
 * Paravirtualized IOMMU driver interface.
 *
 * Copyright (c) 2024 Teddy Astie <teddy.astie@vates.tech>
 */

#ifndef __XEN_PUBLIC_PV_IOMMU_H__
#define __XEN_PUBLIC_PV_IOMMU_H__

#include "xen.h"
#include "physdev.h"

#ifndef uint64_aligned_t
#define uint64_aligned_t uint64_t
#endif

#define IOMMU_DEFAULT_CONTEXT (0)

enum pv_iommu_cmd {
    /* Basic cmd */
    IOMMU_noop = 0,
    IOMMU_query_capabilities = 1,
    IOMMU_init = 2,
    IOMMU_alloc_context = 3,
    IOMMU_free_context = 4,
    IOMMU_reattach_device = 5,
    IOMMU_map_pages = 6,
    IOMMU_unmap_pages = 7,
    IOMMU_remote_cmd = 8,

    /* Extended cmd */
    IOMMU_alloc_nested = 9,      /* if IOMMUCAP_nested */
    IOMMU_flush_nested = 10,     /* if IOMMUCAP_nested */
    IOMMU_attach_pasid = 11,     /* if IOMMUCAP_pasid */
    IOMMU_detach_pasid = 12,     /* if IOMMUCAP_pasid */
};

/**
 * If set, default context allow DMA to domain memory.
 * If cleared, default context blocks all DMA to domain memory.
 */
#define IOMMUCAP_default_identity  (1U << 0)

/**
 * IOMMU_MAP_cache support.
 */
#define IOMMUCAP_cache     (1U << 1)

/**
 * If set, IOMMU_alloc_nested and IOMMU_flush_nested are supported.
 */
#define IOMMUCAP_nested    (1U << 2)

/**
 * If set, IOMMU_attach_pasid and IOMMU_detach_pasid are supported and
 * a device PASID can be specified in reattach_context.
 */
#define IOMMUCAP_pasid     (1U << 3)

/**
 * If set, IOMMU_ALLOC_identity is supported in pv_iommu_alloc.
 */
#define IOMMUCAP_identity  (1U << 4)

/**
 * IOMMU_query_capabilities
 * Query PV-IOMMU capabilities for this domain.
 */
struct pv_iommu_capabilities {
    /*
     * OUT: Maximum device address (iova) that the guest can use for mappings.
     */
    uint64_aligned_t max_iova_addr;

    /* OUT: IOMMU capabilities flags */
    uint32_t cap_flags;

    /* OUT: Mask of all supported page sizes. */
    uint32_t pgsize_mask;

    /* OUT: Maximum pasid (if IOMMUCAP_pasid) */
    uint32_t max_pasid;

    /* OUT: Maximum number of IOMMU context this domain can use. */
    uint16_t max_ctx_no;

    uint16_t pad0;
};
typedef struct pv_iommu_capabilities pv_iommu_capabilities_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_capabilities_t);

/**
 * IOMMU_init
 * Initialize PV-IOMMU for this domain.
 *
 * Fails with -EACCESS if PV-IOMMU is already initialized.
 */
struct pv_iommu_init {
    /* IN: Maximum number of IOMMU context this domain can use. */
    uint32_t max_ctx_no;

    /* IN: Arena size in pages (in power of two) */
    uint32_t arena_order;
};
typedef struct pv_iommu_init pv_iommu_init_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_init_t);

/**
 * Create a 1:1 identity mapped context to domain memory
 * (needs IOMMUCAP_identity).
 */
#define IOMMU_ALLOC_identity (1 << 0)

/**
 * IOMMU_alloc_context
 * Allocate an IOMMU context.
 * Fails with -ENOSPC if no context number is available.
 */
struct pv_iommu_alloc {
    /* OUT: allocated IOMMU context number */
    uint16_t ctx_no;

    /* IN: allocation flags */
    uint32_t alloc_flags;
};
typedef struct pv_iommu_alloc pv_iommu_alloc_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_alloc_t);

/**
 * Move all devices to default context before freeing the context.
 */
#define IOMMU_FREE_reattach_default (1 << 0)

/**
 * IOMMU_free_context
 * Destroy a IOMMU context.
 *
 * If IOMMU_FREE_reattach_default is specified, move all context devices to
 * default context before destroying this context.
 *
 * If there are devices in the context and IOMMU_FREE_reattach_default is not
 * specified, fail with -EBUSY.
 *
 * The default context can't be destroyed.
 */
struct pv_iommu_free {
    /* IN: IOMMU context number to free */
    uint16_t ctx_no;

    /* IN: Free operation specific flags */
    uint32_t free_flags;
};
typedef struct pv_iommu_free pv_iommu_free_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_free_t);

/* Device has read access */
#define IOMMU_MAP_readable (1 << 0)

/* Device has write access */
#define IOMMU_MAP_writeable (1 << 1)

/* Enforce DMA coherency */
#define IOMMU_MAP_cache (1 << 2)

/**
 * IOMMU_map_pages
 * Map pages on a IOMMU context.
 *
 * pgsize must be supported by pgsize_mask.
 * Fails with -EINVAL if mapping on top of another mapping.
 * Report actually mapped page count in mapped field (regardless of failure).
 */
struct pv_iommu_map_pages {
    /* IN: IOMMU context number */
    uint16_t ctx_no;

    /* IN: Guest frame number */
    uint64_aligned_t gfn;

    /* IN: Device frame number */
    uint64_aligned_t dfn;

    /* IN: Map flags */
    uint32_t map_flags;

    /* IN: Size of pages to map */
    uint32_t pgsize;

    /* IN: Number of pages to map */
    uint32_t nr_pages;

    /* OUT: Number of pages actually mapped */
    uint32_t mapped;
};
typedef struct pv_iommu_map_pages pv_iommu_map_pages_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_map_pages_t);

/**
 * IOMMU_unmap_pages
 * Unmap pages on a IOMMU context.
 *
 * pgsize must be supported by pgsize_mask.
 * Report actually unmapped page count in mapped field (regardless of failure).
 * Fails with -ENOENT when attempting to unmap a page without any mapping
 */
struct pv_iommu_unmap_pages {
    /* IN: IOMMU context number */
    uint16_t ctx_no;

    /* IN: Device frame number */
    uint64_aligned_t dfn;

    /* IN: Size of pages to unmap */
    uint32_t pgsize;

    /* IN: Number of pages to unmap */
    uint32_t nr_pages;

    /* OUT: Number of pages actually unmapped */
    uint32_t unmapped;
};
typedef struct pv_iommu_unmap_pages pv_iommu_unmap_pages_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_unmap_pages_t);

/**
 * IOMMU_reattach_device
 * Reattach a device to another IOMMU context.
 * Fails with -ENODEV if no such device exist.
 */
struct pv_iommu_reattach_device {
    /* IN: Target IOMMU context number */
    uint16_t ctx_no;

    /* IN: Physical device to move */
    struct physdev_pci_device dev;

    /* IN: PASID of the device (if IOMMUCAP_pasid) */
    uint32_t pasid;
};
typedef struct pv_iommu_reattach_device pv_iommu_reattach_device_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_reattach_device_t);


/**
 * IOMMU_remote_cmd
 * Do a PV-IOMMU operation on another domain.
 * Current domain needs to be allowed to act on the target domain, otherwise
 * fails with -EPERM.
 */
struct pv_iommu_remote_cmd {
    /* IN: Target domain to do the subop on */
    uint16_t domid;

    /* IN: Command to do on target domain. */
    uint16_t subop;

    /* INOUT: Command argument from current domain memory */
    XEN_GUEST_HANDLE(void) arg;
};
typedef struct pv_iommu_remote_cmd pv_iommu_remote_cmd_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_remote_cmd_t);

/**
 * IOMMU_alloc_nested
 * Create a nested IOMMU context (needs IOMMUCAP_nested).
 *
 * This context uses a platform-specific page table from domain address space
 * specified in pgtable_gfn and use it for nested translations.
 *
 * Explicit flushes needs to be submited with IOMMU_flush_nested on
 * modification of the nested pagetable to ensure coherency between IOTLB and
 * nested page table.
 *
 * This context can be destroyed using IOMMU_free_context.
 * This context cannot be modified using map_pages, unmap_pages.
 */
struct pv_iommu_alloc_nested {
    /* OUT: allocated IOMMU context number */
    uint16_t ctx_no;

    /* IN: guest frame number of the nested page table */
    uint64_aligned_t pgtable_gfn;

    /* IN: nested mode flags */
    uint64_aligned_t nested_flags;
};
typedef struct pv_iommu_alloc_nested pv_iommu_alloc_nested_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_alloc_nested_t);

/**
 * IOMMU_flush_nested (needs IOMMUCAP_nested)
 * Flush the IOTLB for nested translation.
 */
struct pv_iommu_flush_nested {
    /* TODO */
};
typedef struct pv_iommu_flush_nested pv_iommu_flush_nested_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_flush_nested_t);

/**
 * IOMMU_attach_pasid (needs IOMMUCAP_pasid)
 * Attach a new device-with-pasid to a IOMMU context.
 * If a matching device-with-pasid already exists (globally),
 * fail with -EEXIST.
 * If pasid is 0, fails with -EINVAL.
 * If physical device doesn't exist in domain, fail with -ENOENT.
 */
struct pv_iommu_attach_pasid {
    /* IN: IOMMU context to add the device-with-pasid in */
    uint16_t ctx_no;

    /* IN: Physical device */
    struct physdev_pci_device dev;

    /* IN: pasid of the device to attach */
    uint32_t pasid;
};
typedef struct pv_iommu_attach_pasid pv_iommu_attach_pasid_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_attach_pasid_t);

/**
 * IOMMU_detach_pasid (needs IOMMUCAP_pasid)
 * detach a device-with-pasid.
 * If the device-with-pasid doesn't exist or belong to the domain,
 * fail with -ENOENT.
 * If pasid is 0, fails with -EINVAL.
 */
struct pv_iommu_detach_pasid {
    /* IN: Physical device */
    struct physdev_pci_device dev;

    /* pasid of the device to detach */
    uint32_t pasid;
};
typedef struct pv_iommu_detach_pasid pv_iommu_detach_pasid_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_detach_pasid_t);

/* long do_iommu_op(int subop, XEN_GUEST_HANDLE_PARAM(void) arg) */

#endif