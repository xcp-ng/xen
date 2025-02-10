/*
 * Copyright (c) 2006, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 */

#ifndef XEN__IOMMU_H
#define XEN__IOMMU_H

#include <xen/mm-frame.h>
#include <xen/init.h>
#include <xen/page-defs.h>
#include <xen/pci.h>
#include <xen/spinlock.h>
#include <xen/errno.h>
#include <public/domctl.h>
#include <public/hvm/ioreq.h>
#include <asm/device.h>

TYPE_SAFE(uint64_t, dfn);
#define PRI_dfn     PRIx64
#define INVALID_DFN _dfn(~0ULL)

#if 0
#define dfn_t /* Grep fodder: dfn_t, _dfn() and dfn_x() are defined above */
#define _dfn
#define dfn_x
#endif

extern uint64_t bfn_foreign_offset;
int can_use_iommu_check(struct domain *d);

static inline dfn_t __must_check dfn_add(dfn_t dfn, unsigned long i)
{
    return _dfn(dfn_x(dfn) + i);
}

static inline bool dfn_eq(dfn_t x, dfn_t y)
{
    return dfn_x(x) == dfn_x(y);
}

#ifdef CONFIG_HAS_PASSTHROUGH
extern bool iommu_enable, iommu_enabled;
extern bool force_iommu, iommu_verbose;
/* Boolean except for the specific purposes of drivers/passthrough/iommu.c. */
extern uint8_t iommu_quarantine;
#else
#define iommu_enabled false
#endif

#ifdef CONFIG_X86
extern enum __packed iommu_intremap {
   iommu_intremap_off,
   /*
    * Interrupt remapping enabled, but only able to generate interrupts
    * with an 8-bit APIC ID.
    */
   iommu_intremap_restricted,
   iommu_intremap_full,
} iommu_intremap;
extern bool iommu_igfx, iommu_qinval;
#ifdef CONFIG_INTEL_IOMMU
extern bool iommu_snoop;
#else
# define iommu_snoop true
#endif /* CONFIG_INTEL_IOMMU */
#else
# define iommu_intremap false
# define iommu_snoop false
#endif

#if defined(CONFIG_X86) && defined(CONFIG_HVM)
extern bool iommu_intpost;
#else
# define iommu_intpost false
#endif

#if defined(CONFIG_IOMMU_FORCE_PT_SHARE)
#define iommu_hap_pt_share true
#elif defined(CONFIG_HVM)
extern bool iommu_hap_pt_share;
#else
#define iommu_hap_pt_share false
#endif

static inline void clear_iommu_hap_pt_share(void)
{
#ifndef iommu_hap_pt_share
    iommu_hap_pt_share = false;
#elif iommu_hap_pt_share
    ASSERT_UNREACHABLE();
#endif
}

extern bool iommu_debug;
extern bool amd_iommu_perdev_intremap;

extern bool iommu_hwdom_strict, iommu_hwdom_passthrough, iommu_hwdom_inclusive;
extern bool iommu_hwdom_no_dma;
extern int8_t iommu_hwdom_reserved;

extern unsigned int iommu_dev_iotlb_timeout;

int iommu_setup(void);
int iommu_hardware_setup(void);

int iommu_domain_init(struct domain *d, unsigned int opts);
void iommu_hwdom_init(struct domain *d);
void iommu_domain_destroy(struct domain *d);

void arch_iommu_domain_destroy(struct domain *d);
int arch_iommu_domain_init(struct domain *d);
void arch_iommu_check_autotranslated_hwdom(struct domain *d);
void arch_iommu_hwdom_init(struct domain *d);

/*
 * The following flags are passed to map (applicable ones also to unmap)
 * operations, while some are passed back by lookup operations.
 */
#define IOMMUF_order(n)  ((n) & 0x3f)
#define _IOMMUF_readable 6
#define IOMMUF_readable  (1u<<_IOMMUF_readable)
#define _IOMMUF_writable 7
#define IOMMUF_writable  (1u<<_IOMMUF_writable)
#define IOMMUF_preempt   (1u << 8)

/*
 * flush_flags:
 *
 * IOMMU_FLUSHF_added -> A new 'present' PTE has been inserted.
 * IOMMU_FLUSHF_modified -> An existing 'present' PTE has been modified
 *                          (whether the new PTE value is 'present' or not).
 *
 * These flags are passed back from map/unmap operations and passed into
 * flush operations.
 */
enum
{
    _IOMMU_FLUSHF_added,
    _IOMMU_FLUSHF_modified,
    _IOMMU_FLUSHF_all,
};
#define IOMMU_FLUSHF_added (1u << _IOMMU_FLUSHF_added)
#define IOMMU_FLUSHF_modified (1u << _IOMMU_FLUSHF_modified)
#define IOMMU_FLUSHF_all (1u << _IOMMU_FLUSHF_all)

struct iommu_context;

/*
 * For both of these: Negative return values are error indicators. Zero
 * indicates full successful completion of the request, while positive
 * values indicate partial completion, which is possible only with
 * IOMMUF_preempt passed in.
 */
long __must_check iommu_map(struct domain *d, struct iommu_context *ctx,
                            dfn_t dfn0, mfn_t mfn0, unsigned long page_count,
                            unsigned int flags, unsigned int *flush_flags);
long __must_check iommu_unmap(struct domain *d, struct iommu_context *ctx,
                              dfn_t dfn0, unsigned long page_count,
                              unsigned int flags, unsigned int *flush_flags);

int __must_check iommu_legacy_map(struct domain *d, dfn_t dfn, mfn_t mfn,
                                  unsigned long page_count,
                                  unsigned int flags);
int __must_check iommu_legacy_unmap(struct domain *d, dfn_t dfn,
                                    unsigned long page_count);

int __must_check iommu_lookup_page(struct domain *d, struct iommu_context *ctx,
                                   dfn_t dfn, mfn_t *mfn, unsigned int *flags);

int __must_check iommu_iotlb_flush(struct domain *d, struct iommu_context *ctx,
                                   dfn_t dfn, unsigned long page_count,
                                   unsigned int flush_flags);
int __must_check iommu_iotlb_flush_all(struct domain *d,
                                       struct iommu_context *ctx,
                                       unsigned int flush_flags);

enum iommu_feature
{
    IOMMU_FEAT_COHERENT_WALK,
    IOMMU_FEAT_XS_PV_IOMMU,
    IOMMU_FEAT_count
};

bool iommu_has_feature(struct domain *d, enum iommu_feature feature);

#ifdef CONFIG_HAS_PCI
struct pirq;
int hvm_do_IRQ_dpci(struct domain *d, struct pirq *pirq);
int pt_irq_create_bind(struct domain *d,
                       const struct xen_domctl_bind_pt_irq *pt_irq_bind);
int pt_irq_destroy_bind(struct domain *d,
                        const struct xen_domctl_bind_pt_irq *pt_irq_bind);

struct hvm_irq_dpci *domain_get_irq_dpci(const struct domain *d);
void free_hvm_irq_dpci(struct hvm_irq_dpci *dpci);

struct msi_desc;
struct msi_msg;

#define PT_IRQ_TIME_OUT MILLISECS(8)
#endif /* HAS_PCI */

#ifdef CONFIG_HAS_DEVICE_TREE
#include <xen/device_tree.h>

int iommu_assign_dt_device(struct domain *d, struct dt_device_node *dev);
int iommu_deassign_dt_device(struct domain *d, struct dt_device_node *dev);
int iommu_dt_domain_init(struct domain *d);
int iommu_release_dt_devices(struct domain *d);

/*
 * Helper to add master device to the IOMMU using generic IOMMU DT bindings.
 *
 * Return values:
 *  0 : device is protected by an IOMMU
 * <0 : device is not protected by an IOMMU, but must be (error condition)
 * >0 : device doesn't need to be protected by an IOMMU
 *      (IOMMU is not enabled/present or device is not connected to it).
 */
int iommu_add_dt_device(struct dt_device_node *np);

int iommu_do_dt_domctl(struct xen_domctl *domctl, struct domain *d,
                       XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);

/*
 * Helper to remove master device from the IOMMU.
 *
 * Return values:
 *  0 : device is de-registered from IOMMU.
 * <0 : error while removing the device from IOMMU.
 * >0 : IOMMU is not enabled/present.
 */
int iommu_remove_dt_device(struct dt_device_node *np);

#endif /* HAS_DEVICE_TREE */

struct page_info;

/*
 * Any non-zero value returned from callbacks of this type will cause the
 * function the callback was handed to terminate its iteration. Assigning
 * meaning of these non-zero values is left to the top level caller /
 * callback pair.
 */
typedef int iommu_grdm_t(xen_pfn_t start, xen_ulong_t nr, u32 id, void *ctxt);

#define IOMMU_INVALID_CONTEXT_ID 0xFFFF

struct iommu_context;

struct iommu_ops {
    unsigned long page_sizes;
    int (*init)(struct domain *d);
    void (*hwdom_init)(struct domain *d);
    int (*context_init)(struct domain *d, struct iommu_context *ctx,
                        u32 flags);
    int (*context_teardown)(struct domain *d, struct iommu_context *ctx, uint32_t flags);
    int (*attach)(struct domain *d, device_t *dev,
                  struct iommu_context *ctx);
    int (*detach)(struct domain *d, device_t *dev,
                   struct iommu_context *prev_ctx);
    int (*reattach)(struct domain *d, device_t *dev,
                    struct iommu_context *prev_ctx,
                    struct iommu_context *ctx);

#ifdef CONFIG_HAS_PCI
    int (*get_device_group_id)(uint16_t seg, uint8_t bus, uint8_t devfn);
    int (*add_devfn)(struct domain *d, struct pci_dev *pdev, u16 devfn,
                     struct iommu_context *ctx);
    int (*remove_devfn)(struct domain *d, struct pci_dev *pdev, u16 devfn,
                        struct iommu_context *prev_ctx);
#endif /* HAS_PCI */

    void (*teardown)(struct domain *d);

    /*
     * This block of operations must be appropriately locked against each
     * other by the caller in order to have meaningful results.
     */
    int __must_check (*map_page)(struct domain *d, struct iommu_context *ctx,
                                 dfn_t dfn, mfn_t mfn, unsigned int flags,
                                 unsigned int *flush_flags);
    int __must_check (*unmap_page)(struct domain *d, struct iommu_context *ctx,
                                   dfn_t dfn, unsigned int order,
                                   unsigned int *flush_flags);
    int __must_check (*lookup_page)(struct domain *d, struct iommu_context *ctx,
                                    dfn_t dfn, mfn_t *mfn, unsigned int *flags);

#ifdef CONFIG_X86
    int (*enable_x2apic)(void);
    void (*disable_x2apic)(void);

    void (*update_ire_from_apic)(unsigned int apic, unsigned int pin,
                                 uint64_t rte);
    unsigned int (*read_apic_from_ire)(unsigned int apic, unsigned int reg);

    int (*setup_hpet_msi)(struct msi_desc *msi_desc);

    void (*adjust_irq_affinities)(void);
    void (*clear_root_pgtable)(struct domain *d, struct iommu_context *ctx);
    int (*update_ire_from_msi)(struct msi_desc *msi_desc, struct msi_msg *msg);
#endif /* CONFIG_X86 */

    int __must_check (*suspend)(void);
    void (*resume)(void);
    void (*crash_shutdown)(void);
    int __must_check (*iotlb_flush)(struct domain *d,
                                    const struct iommu_context *ctx, dfn_t dfn,
                                    unsigned long page_count,
                                    unsigned int flush_flags);
    int (*get_reserved_device_memory)(iommu_grdm_t *func, void *ctxt);
    void (*dump_page_tables)(struct domain *d);

#ifdef CONFIG_HAS_DEVICE_TREE
    /*
     * All IOMMU drivers which support generic IOMMU DT bindings should use
     * this callback. This is a way for the framework to provide the driver
     * with DT IOMMU specifier which describes the IOMMU master interfaces of
     * that device (device IDs, etc).
     */
    int (*dt_xlate)(device_t *dev, const struct dt_phandle_args *args);
#endif
    /* Inhibit all interrupt generation, to be used at shutdown. */
    void (*quiesce)(void);

    /* Get maximum domain device address (IOVA). */
    uint64_t (*get_max_iova)(struct domain *d);
};

/*
 * To be called by Xen internally, to register extra RMRR/IVMD ranges for RAM
 * pages.
 * Needs to be called before IOMMU initialization.
 */
extern int iommu_add_extra_reserved_device_memory(unsigned long start,
                                                  unsigned long nr,
                                                  pci_sbdf_t sbdf,
                                                  const char *name);
/*
 * To be called by specific IOMMU driver during initialization,
 * to fetch ranges registered with iommu_add_extra_reserved_device_memory().
 * This has a side effect of marking requested ranges as "reserved" in the
 * memory map.
 */
extern int iommu_get_extra_reserved_device_memory(iommu_grdm_t *func,
                                                  void *ctxt);

#ifdef CONFIG_HAS_PASSTHROUGH
#include <asm/iommu.h>
#endif

#ifndef iommu_call
# define iommu_call(ops, fn, args...) ((ops)->fn(args))
# define iommu_vcall iommu_call
#endif

struct iommu_context {
    #ifdef CONFIG_HAS_PASSTHROUGH
    uint16_t id; /* Context id (0 means default context) */
    rspinlock_t lock; /* context lock */

    struct list_head devices;

    struct arch_iommu_context arch;

    bool opaque; /* context can't be modified nor accessed (e.g HAP) */
    bool dying; /* the context is tearing down */
    #endif
};

struct iommu_context_list {
    atomic_t initialized; /* has/is context list being initialized ? */
    rwlock_t lock; /* prevent concurrent destruction and access of contexts */
    uint16_t count; /* Context count excluding default context */

    /* if count > 0 */

    unsigned long *bitmap; /* bitmap of context allocation */
    struct iommu_context *map; /* Map of contexts */
};


struct domain_iommu {

#ifdef CONFIG_HAS_PASSTHROUGH
    struct arch_iommu arch;

    struct iommu_context default_ctx;
    struct iommu_context_list other_contexts;
#endif

    /* iommu_ops */
    const struct iommu_ops *platform_ops;

#ifdef CONFIG_HAS_DEVICE_TREE
    /* List of DT devices assigned to this domain */
    struct list_head dt_devices;
#endif

#ifdef CONFIG_NUMA
    /* NUMA node to do IOMMU related allocations against. */
    nodeid_t node;
#endif

    /* Features supported by the IOMMU */
    /* SAF-2-safe enum constant in arithmetic operation */
    DECLARE_BITMAP(features, IOMMU_FEAT_count);

    /* Do the IOMMU block all DMA on default context (implies !has_pt_share) ? */
    bool no_dma;

    /* Is the domain allowed to use PV-IOMMU ? */
    bool allow_pv_iommu;

    /* Does the guest share HAP mapping with the IOMMU? */
    bool hap_pt_share;

    /*
     * Does the guest require mappings to be synchronized, to maintain
     * the default dfn == pfn map? (See comment on dfn at the top of
     * include/xen/mm.h). Note that hap_pt_share == false does not
     * necessarily imply this is true.
     */
    bool need_sync;
};

#define dom_iommu(d)              (&(d)->iommu)
#define iommu_set_feature(d, f)   set_bit(f, dom_iommu(d)->features)
#define iommu_clear_feature(d, f) clear_bit(f, dom_iommu(d)->features)
#define iommu_default_context(d) (&dom_iommu(d)->default_ctx) /* does not lock ! */

/* Are we using the domain P2M table as its IOMMU pagetable? */
#define iommu_use_hap_pt(d)       (IS_ENABLED(CONFIG_HVM) && \
                                   dom_iommu(d)->hap_pt_share)

/* Does the IOMMU pagetable need to be kept synchronized with the P2M */
#ifdef CONFIG_HAS_PASSTHROUGH
#define need_iommu_pt_sync(d)     (dom_iommu(d)->need_sync)

int iommu_do_domctl(struct xen_domctl *domctl, struct domain *d,
                    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);
#else
#define need_iommu_pt_sync(d)     ({ (void)(d); false; })

static inline int iommu_do_domctl(struct xen_domctl *domctl, struct domain *d,
                                  XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    return -ENOSYS;
}
#endif

int iommu_domain_pviommu_init(struct domain *d, uint16_t nb_ctx, uint32_t arena_order);

int __must_check iommu_suspend(void);
void iommu_resume(void);
void iommu_crash_shutdown(void);
void iommu_quiesce(void);
int iommu_get_reserved_device_memory(iommu_grdm_t *func, void *ctxt);

int __init iommu_quarantine_init(void);
int iommu_quarantine_dev_init(device_t *dev);

#ifdef CONFIG_HAS_PCI
int iommu_do_pci_domctl(struct xen_domctl *domctl, struct domain *d,
                        XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);
#endif

void iommu_dev_iotlb_flush_timeout(struct domain *d, struct pci_dev *pdev);

uint64_t iommu_get_max_iova(struct domain *d);

struct iommu_context *iommu_get_context(struct domain *d, u16 ctx_id);
void iommu_put_context(struct iommu_context *ctx);

#define IOMMU_CONTEXT_INIT_default (1 << 0)
#define IOMMU_CONTEXT_INIT_quarantine (1 << 1)
int iommu_context_init(struct domain *d, struct iommu_context *ctx, u16 ctx_id, u32 flags);

#define IOMMU_TEARDOWN_REATTACH_DEFAULT (1 << 0)
#define IOMMU_TEARDOWN_PREEMPT (1 << 1)
int iommu_context_teardown(struct domain *d, struct iommu_context *ctx, u32 flags);

int iommu_context_alloc(struct domain *d, u16 *ctx_id, u32 flags);
int iommu_context_free(struct domain *d, u16 ctx_id, u32 flags);

int iommu_reattach_context(struct domain *prev_dom, struct domain *next_dom,
                           device_t *dev, u16 ctx_id);
int iommu_attach_context(struct domain *d, device_t *dev, u16 ctx_id);
int iommu_detach_context(struct domain *d, device_t *dev);

/*
 * The purpose of the iommu_dont_flush_iotlb optional cpu flag is to
 * avoid unecessary iotlb_flush in the low level IOMMU code.
 *
 * iommu_map_page/iommu_unmap_page must flush the iotlb but somethimes
 * this operation can be really expensive. This flag will be set by the
 * caller to notify the low level IOMMU code to avoid the iotlb flushes.
 * iommu_iotlb_flush/iommu_iotlb_flush_all will be explicitly called by
 * the caller.
 */
DECLARE_PER_CPU(bool, iommu_dont_flush_iotlb);

extern struct spinlock iommu_pt_cleanup_lock;
extern struct page_list_head iommu_pt_cleanup_list;

int arch_iommu_pviommu_init(struct domain *d, uint16_t nb_ctx, uint32_t arena_order);
int arch_iommu_pviommu_teardown(struct domain *d);
bool arch_iommu_use_permitted(const struct domain *d);

#ifdef CONFIG_X86
/*
 * Return values:
 *  - < 0 on error.
 *  - 0 on success and no need to write msi_msg to the hardware.
 *  - 1 on success and msi_msg must be propagated to the hardware.
 */
static inline int iommu_update_ire_from_msi(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    return iommu_intremap
           ? iommu_call(&iommu_ops, update_ire_from_msi, msi_desc, msg) : 0;
}
#endif

#endif /* XEN__IOMMU_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
