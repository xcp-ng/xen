/*
 * Copyright (C) 2008,  Netronome Systems, Inc.
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
 */

#include <xen/sched.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/pci_ids.h>
#include <xen/list.h>
#include <xen/prefetch.h>
#include <xen/iommu.h>
#include <xen/irq.h>
#include <xen/param.h>
#include <xen/delay.h>
#include <xen/keyhandler.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/paging.h>
#include <xen/rangeset.h>
#include <xen/radix-tree.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xen/vpci.h>
#include <xen/msi.h>
#include <xen/lockdown.h>
#include <xsm/xsm.h>
#include "ats.h"

struct pci_seg {
    struct list_head alldevs_list;
    u16 nr;
    unsigned long *ro_map;
    /* bus2bridge_lock protects bus2bridge array */
    spinlock_t bus2bridge_lock;
#define MAX_BUSES 256
    struct {
        u8 map;
        u8 bus;
        u8 devfn;
    } bus2bridge[MAX_BUSES];
};

static DEFINE_RSPINLOCK(_pcidevs_lock);

static int pdev_config_writable_init(struct pci_dev *pdev);

/* Do not use, as it has no speculation barrier, use pcidevs_lock() instead. */
void pcidevs_lock_unsafe(void)
{
    _rspin_lock(&_pcidevs_lock);
}

void pcidevs_unlock(void)
{
    rspin_unlock(&_pcidevs_lock);
}

bool pcidevs_locked(void)
{
    return rspin_is_locked(&_pcidevs_lock);
}

bool pcidevs_trylock_unsafe(void)
{
    return _rspin_trylock(&_pcidevs_lock);
}

static RADIX_TREE(pci_segments);

static inline struct pci_seg *get_pseg(u16 seg)
{
    return radix_tree_lookup(&pci_segments, seg);
}

bool pci_known_segment(u16 seg)
{
    return get_pseg(seg) != NULL;
}

static struct pci_seg *alloc_pseg(u16 seg)
{
    struct pci_seg *pseg = get_pseg(seg);

    if ( pseg )
        return pseg;

    pseg = xzalloc(struct pci_seg);
    if ( !pseg )
        return NULL;

    pseg->nr = seg;
    INIT_LIST_HEAD(&pseg->alldevs_list);
    spin_lock_init(&pseg->bus2bridge_lock);

    if ( radix_tree_insert(&pci_segments, seg, pseg) )
    {
        xfree(pseg);
        pseg = NULL;
    }

    return pseg;
}

static int pci_segments_iterate(
    int (*handler)(struct pci_seg *pseg, void *arg), void *arg)
{
    uint16_t seg = 0;
    int rc = 0;

    do {
        struct pci_seg *pseg;

        if ( !radix_tree_gang_lookup(&pci_segments, (void **)&pseg, seg, 1) )
            break;
        rc = handler(pseg, arg);
        seg = pseg->nr + 1;
    } while (!rc && seg);

    return rc;
}

void __init pci_segments_init(void)
{
    if ( !alloc_pseg(0) )
        panic("Could not initialize PCI segment 0\n");
}

int __init pci_add_segment(u16 seg)
{
    return alloc_pseg(seg) ? 0 : -ENOMEM;
}

const unsigned long *pci_get_ro_map(u16 seg)
{
    struct pci_seg *pseg = get_pseg(seg);

    return pseg ? pseg->ro_map : NULL;
}

static struct phantom_dev {
    u16 seg;
    u8 bus, slot, stride;
} phantom_devs[8];
static unsigned int nr_phantom_devs;

static int __init cf_check parse_phantom_dev(const char *str)
{
    const char *s;
    unsigned int seg, bus, slot;
    struct phantom_dev phantom;

    if ( !*str )
        return -EINVAL;
    if ( nr_phantom_devs >= ARRAY_SIZE(phantom_devs) )
        return -E2BIG;

    s = parse_pci(str, &seg, &bus, &slot, NULL);
    if ( !s || *s != ',' )
        return -EINVAL;

    phantom.seg = seg;
    phantom.bus = bus;
    phantom.slot = slot;

    switch ( phantom.stride = simple_strtol(s + 1, &s, 0) )
    {
    case 1: case 2: case 4:
        if ( *s )
            return -EINVAL;
        break;

    default:
        return -EINVAL;
    }

    phantom_devs[nr_phantom_devs++] = phantom;

    return 0;
}
custom_param("pci-phantom", parse_phantom_dev);

static u16 __read_mostly command_mask;
static u16 __read_mostly bridge_ctl_mask;

static int __init cf_check parse_pci_param(const char *s)
{
    const char *ss;
    int rc = 0;

    do {
        int val;
        u16 cmd_mask = 0, brctl_mask = 0;

        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_boolean("serr", s, ss)) >= 0 )
        {
            cmd_mask = PCI_COMMAND_SERR;
            brctl_mask = PCI_BRIDGE_CTL_SERR | PCI_BRIDGE_CTL_DTMR_SERR;
        }
        else if ( (val = parse_boolean("perr", s, ss)) >= 0 )
        {
            cmd_mask = PCI_COMMAND_PARITY;
            brctl_mask = PCI_BRIDGE_CTL_PARITY;
        }
        else
            rc = -EINVAL;

        if ( val )
        {
            command_mask &= ~cmd_mask;
            bridge_ctl_mask &= ~brctl_mask;
        }
        else
        {
            command_mask |= cmd_mask;
            bridge_ctl_mask |= brctl_mask;
        }

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("pci", parse_pci_param);

static void check_pdev(const struct pci_dev *pdev)
{
#define PCI_STATUS_CHECK \
    (PCI_STATUS_PARITY | PCI_STATUS_SIG_TARGET_ABORT | \
     PCI_STATUS_REC_TARGET_ABORT | PCI_STATUS_REC_MASTER_ABORT | \
     PCI_STATUS_SIG_SYSTEM_ERROR | PCI_STATUS_DETECTED_PARITY)
    u16 val;

    if ( command_mask )
    {
        val = pci_conf_read16(pdev->sbdf, PCI_COMMAND);
        if ( val & command_mask )
            pci_conf_write16(pdev->sbdf, PCI_COMMAND, val & ~command_mask);
        val = pci_conf_read16(pdev->sbdf, PCI_STATUS);
        if ( val & PCI_STATUS_CHECK )
        {
            printk(XENLOG_INFO "%pp status %04x -> %04x\n",
                   &pdev->sbdf, val, val & ~PCI_STATUS_CHECK);
            pci_conf_write16(pdev->sbdf, PCI_STATUS, val & PCI_STATUS_CHECK);
        }
    }

    switch ( pci_conf_read8(pdev->sbdf, PCI_HEADER_TYPE) & 0x7f )
    {
    case PCI_HEADER_TYPE_BRIDGE:
        if ( !bridge_ctl_mask )
            break;
        val = pci_conf_read16(pdev->sbdf, PCI_BRIDGE_CONTROL);
        if ( val & bridge_ctl_mask )
            pci_conf_write16(pdev->sbdf, PCI_BRIDGE_CONTROL,
                             val & ~bridge_ctl_mask);
        val = pci_conf_read16(pdev->sbdf, PCI_SEC_STATUS);
        if ( val & PCI_STATUS_CHECK )
        {
            printk(XENLOG_INFO "%pp secondary status %04x -> %04x\n",
                   &pdev->sbdf, val, val & ~PCI_STATUS_CHECK);
            pci_conf_write16(pdev->sbdf, PCI_SEC_STATUS,
                             val & PCI_STATUS_CHECK);
        }
        break;

    case PCI_HEADER_TYPE_CARDBUS:
        /* TODO */
        break;
    }
#undef PCI_STATUS_CHECK
}

static void apply_quirks(struct pci_dev *pdev)
{
    uint16_t vendor = pci_conf_read16(pdev->sbdf, PCI_VENDOR_ID);
    uint16_t device = pci_conf_read16(pdev->sbdf, PCI_DEVICE_ID);
    static const struct {
        uint16_t vendor, device;
    } ignore_bars[] = {
        /*
         * Device [8086:2fc0]
         * Erratum HSE43
         * CONFIG_TDP_NOMINAL CSR Implemented at Incorrect Offset
         * http://www.intel.com/content/www/us/en/processors/xeon/xeon-e5-v3-spec-update.html 
         */
        { PCI_VENDOR_ID_INTEL, 0x2fc0 },
        /*
         * Devices [8086:6f60,6fa0,6fc0]
         * Errata BDF2 / BDX2
         * PCI BARs in the Home Agent Will Return Non-Zero Values During Enumeration
         * http://www.intel.com/content/www/us/en/processors/xeon/xeon-e5-v4-spec-update.html 
        */
        { PCI_VENDOR_ID_INTEL, 0x6f60 },
        { PCI_VENDOR_ID_INTEL, 0x6fa0 },
        { PCI_VENDOR_ID_INTEL, 0x6fc0 },
    };
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(ignore_bars); i++)
        if ( vendor == ignore_bars[i].vendor &&
             device == ignore_bars[i].device )
            /*
             * For these errata force ignoring the BARs, which prevents vPCI
             * from trying to size the BARs or add handlers to trap accesses.
             */
            pdev->ignore_bars = true;
}

static struct pci_dev *alloc_pdev(struct pci_seg *pseg, u8 bus, u8 devfn)
{
    struct pci_dev *pdev;
    unsigned int pos;
    int rc;

    list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
        if ( pdev->bus == bus && pdev->devfn == devfn )
            return pdev;

    pdev = xzalloc(struct pci_dev);
    if ( !pdev )
        return NULL;

    *(u16*) &pdev->seg = pseg->nr;
    *((u8*) &pdev->bus) = bus;
    *((u8*) &pdev->devfn) = devfn;
    pdev->domain = NULL;
    pdev->context = IOMMU_INVALID_CONTEXT_ID;

    INIT_LIST_HEAD(&pdev->vf_list);

    arch_pci_init_pdev(pdev);

    rc = pdev_msi_init(pdev);
    if ( !rc )
        rc = pdev_config_writable_init(pdev);
    if ( rc )
    {
        xfree(pdev);
        return NULL;
    }

    pdev->sriov_pos =
        pci_find_ext_capability(pdev->sbdf, PCI_EXT_CAP_ID_SRIOV);

    list_add(&pdev->alldevs_list, &pseg->alldevs_list);

    /* update bus2bridge */
    switch ( pdev->type = pdev_type(pseg->nr, bus, devfn) )
    {
        unsigned int cap, sec_bus, sub_bus;
        unsigned long flags;

        case DEV_TYPE_PCIe2PCI_BRIDGE:
        case DEV_TYPE_LEGACY_PCI_BRIDGE:
            sec_bus = pci_conf_read8(pdev->sbdf, PCI_SECONDARY_BUS);
            sub_bus = pci_conf_read8(pdev->sbdf, PCI_SUBORDINATE_BUS);

            spin_lock_irqsave(&pseg->bus2bridge_lock, flags);
            for ( ; sec_bus <= sub_bus; sec_bus++ )
            {
                pseg->bus2bridge[sec_bus].map = 1;
                pseg->bus2bridge[sec_bus].bus = bus;
                pseg->bus2bridge[sec_bus].devfn = devfn;
            }
            spin_unlock_irqrestore(&pseg->bus2bridge_lock, flags);
            break;

        case DEV_TYPE_PCIe_ENDPOINT:
            pos = pci_find_cap_offset(pdev->sbdf, PCI_CAP_ID_EXP);
            BUG_ON(!pos);
            cap = pci_conf_read16(pdev->sbdf, pos + PCI_EXP_DEVCAP);
            if ( cap & PCI_EXP_DEVCAP_PHANTOM )
            {
                pdev->phantom_stride = 8 >> MASK_EXTR(cap,
                                                      PCI_EXP_DEVCAP_PHANTOM);
                if ( PCI_FUNC(devfn) >= pdev->phantom_stride )
                    pdev->phantom_stride = 0;
            }
            else
            {
                unsigned int i;

                for ( i = 0; i < nr_phantom_devs; ++i )
                    if ( phantom_devs[i].seg == pseg->nr &&
                         phantom_devs[i].bus == bus &&
                         phantom_devs[i].slot == PCI_SLOT(devfn) &&
                         phantom_devs[i].stride > PCI_FUNC(devfn) )
                    {
                        pci_sbdf_t sbdf = pdev->sbdf;
                        unsigned int stride = phantom_devs[i].stride;

                        while ( (sbdf.fn += stride) > PCI_FUNC(devfn) )
                        {
                            if ( pci_conf_read16(sbdf, PCI_VENDOR_ID) == 0xffff &&
                                 pci_conf_read16(sbdf, PCI_DEVICE_ID) == 0xffff )
                                continue;
                            stride <<= 1;
                            printk(XENLOG_WARNING
                                   "%pp looks to be a real device; bumping %04x:%02x:%02x stride to %u\n",
                                   &sbdf, phantom_devs[i].seg,
                                   phantom_devs[i].bus, phantom_devs[i].slot,
                                   stride);
                            sbdf = pdev->sbdf;
                        }
                        if ( PCI_FUNC(stride) )
                           pdev->phantom_stride = stride;
                        break;
                    }
            }
            break;

        case DEV_TYPE_PCI:
        case DEV_TYPE_PCIe_BRIDGE:
        case DEV_TYPE_PCI_HOST_BRIDGE:
            break;

        default:
            printk(XENLOG_WARNING "%pp: unknown type %d\n",
                   &pdev->sbdf, pdev->type);
            break;
    }

    apply_quirks(pdev);
    check_pdev(pdev);

    return pdev;
}

static void free_pdev(struct pci_seg *pseg, struct pci_dev *pdev)
{
    /* update bus2bridge */
    switch ( pdev->type )
    {
        unsigned int sec_bus, sub_bus;
        unsigned long flags;

        case DEV_TYPE_PCIe2PCI_BRIDGE:
        case DEV_TYPE_LEGACY_PCI_BRIDGE:
            sec_bus = pci_conf_read8(pdev->sbdf, PCI_SECONDARY_BUS);
            sub_bus = pci_conf_read8(pdev->sbdf, PCI_SUBORDINATE_BUS);

            spin_lock_irqsave(&pseg->bus2bridge_lock, flags);
            for ( ; sec_bus <= sub_bus; sec_bus++ )
                pseg->bus2bridge[sec_bus] = pseg->bus2bridge[pdev->bus];
            spin_unlock_irqrestore(&pseg->bus2bridge_lock, flags);
            break;

        default:
            break;
    }

    list_del(&pdev->alldevs_list);
    pdev_msi_deinit(pdev);

    if ( pdev->info.is_virtfn )
        list_del(&pdev->vf_list);

    rangeset_destroy(pdev->config_writable);

    xfree(pdev);
}

static void __init _pci_hide_device(struct pci_dev *pdev)
{
    if ( pdev->domain )
        return;
    pdev->domain = dom_xen;
    write_lock(&dom_xen->pci_lock);
    list_add(&pdev->domain_list, &dom_xen->pdev_list);
    write_unlock(&dom_xen->pci_lock);
}

int __init pci_hide_device(unsigned int seg, unsigned int bus,
                           unsigned int devfn)
{
    struct pci_dev *pdev;
    struct pci_seg *pseg;
    int rc = -ENOMEM;

    pcidevs_lock();
    pseg = alloc_pseg(seg);
    if ( pseg )
    {
        pdev = alloc_pdev(pseg, bus, devfn);
        if ( pdev )
        {
            _pci_hide_device(pdev);
            rc = 0;
        }
    }
    pcidevs_unlock();

    return rc;
}

int __init pci_ro_device(int seg, int bus, int devfn)
{
    struct pci_seg *pseg = alloc_pseg(seg);
    struct pci_dev *pdev;

    if ( !pseg )
        return -ENOMEM;
    pdev = alloc_pdev(pseg, bus, devfn);
    if ( !pdev )
        return -ENOMEM;

    if ( !pseg->ro_map )
    {
        size_t sz = BITS_TO_LONGS(PCI_BDF(-1, -1, -1) + 1) * sizeof(long);

        pseg->ro_map = alloc_xenheap_pages(get_order_from_bytes(sz), 0);
        if ( !pseg->ro_map )
            return -ENOMEM;
        memset(pseg->ro_map, 0, sz);
    }

    __set_bit(PCI_BDF(bus, devfn), pseg->ro_map);
    _pci_hide_device(pdev);

    return 0;
}

struct pci_dev *pci_get_real_pdev(pci_sbdf_t sbdf)
{
    struct pci_dev *pdev;
    int stride;

    for ( pdev = pci_get_pdev(NULL, sbdf), stride = 4;
          !pdev && stride; stride >>= 1 )
    {
        if ( !(sbdf.devfn & stride) )
            continue;
        sbdf.devfn &= ~stride;
        pdev = pci_get_pdev(NULL, sbdf);
        if ( pdev && stride != pdev->phantom_stride )
            pdev = NULL;
    }

    return pdev;
}

struct pci_dev *pci_get_pdev(const struct domain *d, pci_sbdf_t sbdf)
{
    struct pci_dev *pdev;

    ASSERT(d || pcidevs_locked());

    /*
     * The hardware domain owns the majority of the devices in the system.
     * When there are multiple segments, traversing the per-segment list is
     * likely going to be faster, whereas for a single segment the difference
     * shouldn't be that large.
     */
    if ( !d || is_hardware_domain(d) )
    {
        const struct pci_seg *pseg = get_pseg(sbdf.seg);

        if ( !pseg )
            return NULL;

        list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
            if ( pdev->sbdf.bdf == sbdf.bdf &&
                 (!d || pdev->domain == d) )
                return pdev;
    }
    else
        list_for_each_entry ( pdev, &d->pdev_list, domain_list )
            if ( pdev->sbdf.sbdf == sbdf.sbdf )
                return pdev;

    return NULL;
}

static bool is_nvidia_legacy_vgpu(uint16_t device_id)
{
    switch ( device_id )
    {
    /* list of Nvidia device IDs implementing legacy vGPU */
    case 0x13bd: /* GM107GL [Tesla M10] */
    case 0x13f2:
    case 0x13f3:
    case 0x15f7:
    case 0x15f8:
    case 0x15f9:
    case 0x1b38:
    case 0x1bb3:
    case 0x1bb4:
    case 0x1db1: /* GV100GL [Tesla V100-SXM2-16GB] */
    case 0x1db3: /* GV100GL [Tesla V100-FHHL-16GB] */
    case 0x1db4: /* GV100GL [Tesla V100-PCIE-16GB] */
    case 0x1db5: /* GV100GL [Tesla V100-SXM2-32GB] */
    case 0x1db6: /* GV100GL [Tesla V100-PCIE-32GB] */
    case 0x1df6: /* GV100GL [Tesla V100S-PCIE-32GB] */
    case 0x1e30: /* TU102GL [Quadro RTX 6000/8000] */
    case 0x1e78: /* TU102GL [Quadro RTX 6000/8000] */
    case 0x1eb8: /* TU104GL [Tesla T4] */
        return true;
    }
    return false;
}

static bool need_cache(const struct pci_dev *pdev, unsigned num_bars)
{
    for ( unsigned i = 0; i < num_bars; i++ )
        if ( pdev->bar[i].type == PCI_BAR_TYPE_EMPTY )
            return true;

    return false;
}

static bool cache_virtfn(struct pci_dev *pdev)
{
    int vf;
    pci_sbdf_t sbdf = pdev->sbdf;
    unsigned int base, pos;
    uint16_t ctrl, num_vf, offset, stride;

    if ( !need_cache(pdev, PCI_SRIOV_NUM_BARS) )
        return true;

    vf = pdev->sbdf.bdf;
    sbdf.bus = pdev->info.physfn.bus;
    sbdf.devfn = pdev->info.physfn.devfn;

    pos = pdev->pf_pdev->sriov_pos;
    if ( !pos )
        return false;

    ctrl = pci_conf_read16(sbdf, pos + PCI_SRIOV_CTRL);
    num_vf = pci_conf_read16(sbdf, pos + PCI_SRIOV_NUM_VF);
    offset = pci_conf_read16(sbdf, pos + PCI_SRIOV_VF_OFFSET);
    stride = pci_conf_read16(sbdf, pos + PCI_SRIOV_VF_STRIDE);

    if ( !(ctrl & PCI_SRIOV_CTRL_VFE) ||
         !(ctrl & PCI_SRIOV_CTRL_MSE) ||
         !num_vf || !offset || (num_vf > 1 && !stride) )
        return false;

    base = pos + PCI_SRIOV_BAR;
    vf -= sbdf.bdf + offset;
    if ( vf < 0 )
        return false;
    if ( stride )
    {
        if ( vf % stride )
            return false;
        vf /= stride;
    }
    if ( vf >= num_vf )
        return false;

    for ( unsigned i = 0; i < PCI_SRIOV_NUM_BARS; i++ )
    {
        uint64_t addr, size;

        if ( pdev->bar[i].type != PCI_BAR_TYPE_EMPTY )
            continue;

        size = pdev->pf_pdev->physfn.vf_rlen[i];
        pdev->bar[i].type = PCI_BAR_TYPE_MEM32;
        pdev->bar[i].size = size;
        pdev->bar[i].addr = 0;
        if ( !size )
            continue;

        addr = pci_conf_read32(sbdf, base + i * 4);
        /*
         * there should not be any I/O BAR for VF, a warning message
         * is printed in pci_add_device.
         */
        if ( (addr & PCI_BASE_ADDRESS_SPACE) !=
              PCI_BASE_ADDRESS_SPACE_MEMORY )
        {
            pdev->bar[i].type = PCI_BAR_TYPE_IO;
            pdev->bar[i].size = 0;
            continue;
        }

        if ( (addr & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
              PCI_BASE_ADDRESS_MEM_TYPE_64 &&
             i < (PCI_SRIOV_NUM_BARS - 1) )
        {
            pdev->bar[i].type = PCI_BAR_TYPE_MEM64_LO;
            ++i;
            pdev->bar[i].type = PCI_BAR_TYPE_MEM64_HI;
            pdev->bar[i].addr = 0;
            pdev->bar[i].size = 0;

            addr &= PCI_BASE_ADDRESS_MEM_MASK;

            addr += vf * size +
                ((uint64_t)pci_conf_read32(sbdf,
                                           base + i * 4) << 32);
            pdev->bar[i - 1].addr = addr;
        }
        else
        {
            addr = (addr & PCI_BASE_ADDRESS_MEM_MASK) + vf * size;
            pdev->bar[i].addr = addr;
        }
    }

    return true;
}

static bool cache_pdev(struct pci_dev *pdev)
{
    unsigned i;

    if ( !need_cache(pdev, PCI_HEADER_NORMAL_NR_BARS) )
        return true;

    if ( (pci_conf_read8(pdev->sbdf, PCI_HEADER_TYPE) & 0x7f) !=
         PCI_HEADER_TYPE_NORMAL )
        return false;

    for ( i = 0; i < PCI_HEADER_NORMAL_NR_BARS; ++i )
    {
        unsigned int idx = PCI_BASE_ADDRESS_0 + i * 4;
        int rc;
        uint32_t bar;

        if ( pdev->bar[i].type != PCI_BAR_TYPE_EMPTY )
            continue;

        bar = pci_conf_read32(pdev->sbdf, idx);

        if ( (bar & PCI_BASE_ADDRESS_SPACE) != PCI_BASE_ADDRESS_SPACE_MEMORY )
        {
            uint32_t size;

            pci_conf_write32(pdev->sbdf, idx, ~0);
            size = pci_conf_read32(pdev->sbdf, idx) & PCI_BASE_ADDRESS_IO_MASK;
            size = ~size + 1;
            pci_conf_write32(pdev->sbdf, idx, bar);

            pdev->bar[i].addr = bar & PCI_BASE_ADDRESS_IO_MASK;
            pdev->bar[i].size = size;
            pdev->bar[i].type = PCI_BAR_TYPE_IO;
            continue;
        }

        rc = pci_size_mem_bar(pdev->sbdf, idx,
                              &pdev->bar[i].addr, &pdev->bar[i].size,
                              (i == PCI_HEADER_NORMAL_NR_BARS - 1) ?
                                  PCI_BAR_LAST : 0);
        if ( rc == 2 )
        {
            pdev->bar[i].type = PCI_BAR_TYPE_MEM64_LO;
            ++i;
            pdev->bar[i].type = PCI_BAR_TYPE_MEM64_HI;
            pdev->bar[i].addr = 0;
            pdev->bar[i].size = 0;
        }
        else
        {
            pdev->bar[i].type = PCI_BAR_TYPE_MEM32;
        }
    }

    /* Handle the ROM BAR */
    i = PCI_HEADER_NORMAL_NR_BARS;
    pdev->bar[i].type = PCI_BAR_TYPE_ROM;
    pdev->bar[i].size = 0;
    pdev->bar[i].addr = 0;
    pci_size_mem_bar(pdev->sbdf, PCI_ROM_ADDRESS,
                     &pdev->bar[i].addr, &pdev->bar[i].size,
                     PCI_BAR_ROM);

    return true;
}

static int check_iomem_access_vgpu(const struct domain *d, xen_pfn_t mfn_start,
                                   xen_pfn_t mfn_end, bool vgpu)
{
    struct pci_dev *pdev;
    int rc = 0;

    pcidevs_lock();
    list_for_each_entry ( pdev, &d->pdev_list, domain_list )
    {
        /* filter out no vGPU if vGPU is required */
        if ( vgpu &&
             (pci_conf_read16(pdev->sbdf, PCI_VENDOR_ID) != PCI_VENDOR_ID_NVIDIA ||
              !is_nvidia_legacy_vgpu(pci_conf_read16(pdev->sbdf, PCI_DEVICE_ID))) )
            continue;

        if ( pdev->info.is_virtfn )
        {
            if ( !cache_virtfn(pdev) )
                continue;
        }
        else
        {
            if ( !cache_pdev(pdev) )
                continue;
        }

        for ( unsigned i = 0; i <= PCI_HEADER_NORMAL_NR_BARS; ++i )
        {
            uint64_t addr, size;

            if ( pdev->bar[i].type != PCI_BAR_TYPE_MEM64_LO &&
                 pdev->bar[i].type != PCI_BAR_TYPE_MEM32 &&
                 pdev->bar[i].type != PCI_BAR_TYPE_ROM )
                continue;

            addr = pdev->bar[i].addr;
            size = pdev->bar[i].size;

            if ( !addr || !size )
                continue;

            if ( mfn_start >= (addr >> PAGE_SHIFT) &&
                 mfn_end <= ((addr + size - 1) >> PAGE_SHIFT) )
                goto out;
        }
    }

    rc = -ENOENT;

out:
    pcidevs_unlock();
    return rc;
}

int check_iomem_access(const struct domain *d, xen_pfn_t mfn_start,
                       xen_pfn_t mfn_end)
{
    int rc;

    if ( !is_locked_down() )
        return 0;

    rc = check_iomem_access_vgpu(d, mfn_start, mfn_end, false);
    if ( rc == 0 ||
         current->domain == d ||
         !is_hardware_domain(current->domain) )
        return rc;

    return check_iomem_access_vgpu(current->domain, mfn_start, mfn_end, true);
}

int check_ioport_access(const struct domain *d, unsigned int port_start,
                        unsigned int port_end)
{
    struct pci_dev *pdev;
    int rc = 0;

    if ( !is_locked_down() )
        return 0;

    pcidevs_lock();
    list_for_each_entry ( pdev, &d->pdev_list, domain_list )
    {
        if ( pdev->info.is_virtfn )
            continue;

        if ( !cache_pdev(pdev) )
            continue;

        for ( unsigned i = 0; i < PCI_HEADER_NORMAL_NR_BARS; i++ )
        {
            uint32_t size, addr;

            if ( pdev->bar[i].type != PCI_BAR_TYPE_IO )
                continue;

            addr = (uint32_t)pdev->bar[i].addr;
            size = (uint32_t)pdev->bar[i].size;

            if ( port_start >= addr && port_end <= (addr + size - 1) )
                goto out;
        }
    }

    rc = -ENOENT;

out:
    pcidevs_unlock();
    return rc;
}

/**
 * pci_enable_acs - enable ACS if hardware support it
 * @dev: the PCI device
 */
static void pci_enable_acs(struct pci_dev *pdev)
{
    int pos;
    uint16_t cap, ctrl;

    if ( !is_iommu_enabled(pdev->domain) )
        return;

    pos = pci_find_ext_capability(pdev->sbdf, PCI_EXT_CAP_ID_ACS);
    if (!pos)
        return;

    cap = pci_conf_read16(pdev->sbdf, pos + PCI_ACS_CAP);
    ctrl = pci_conf_read16(pdev->sbdf, pos + PCI_ACS_CTRL);

    /* Source Validation */
    ctrl |= (cap & PCI_ACS_SV);

    /* P2P Request Redirect */
    ctrl |= (cap & PCI_ACS_RR);

    /* P2P Completion Redirect */
    ctrl |= (cap & PCI_ACS_CR);

    /* Upstream Forwarding */
    ctrl |= (cap & PCI_ACS_UF);

    pci_conf_write16(pdev->sbdf, pos + PCI_ACS_CTRL, ctrl);
}

static int iommu_add_device(struct pci_dev *pdev);
static int iommu_remove_device(struct pci_dev *pdev);

unsigned int pci_size_mem_bar(pci_sbdf_t sbdf, unsigned int pos,
                              uint64_t *paddr, uint64_t *psize,
                              unsigned int flags)
{
    uint32_t hi = 0, bar = pci_conf_read32(sbdf, pos);
    uint64_t size;
    bool is64bits = !(flags & PCI_BAR_ROM) &&
        (bar & PCI_BASE_ADDRESS_MEM_TYPE_MASK) == PCI_BASE_ADDRESS_MEM_TYPE_64;
    uint32_t mask = (flags & PCI_BAR_ROM) ? (uint32_t)PCI_ROM_ADDRESS_MASK
                                          : (uint32_t)PCI_BASE_ADDRESS_MEM_MASK;

    ASSERT(!((flags & PCI_BAR_VF) && (flags & PCI_BAR_ROM)));
    ASSERT((flags & PCI_BAR_ROM) ||
           (bar & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_MEMORY);
    pci_conf_write32(sbdf, pos, ~0);
    if ( is64bits )
    {
        if ( flags & PCI_BAR_LAST )
        {
            printk(XENLOG_WARNING
                   "%sdevice %pp with 64-bit %sBAR in last slot\n",
                   (flags & PCI_BAR_VF) ? "SR-IOV " : "", &sbdf,
                   (flags & PCI_BAR_VF) ? "vf " : "");
            *psize = 0;
            return 1;
        }
        hi = pci_conf_read32(sbdf, pos + 4);
        pci_conf_write32(sbdf, pos + 4, ~0);
    }
    size = pci_conf_read32(sbdf, pos) & mask;
    if ( is64bits )
    {
        size |= (uint64_t)pci_conf_read32(sbdf, pos + 4) << 32;
        pci_conf_write32(sbdf, pos + 4, hi);
    }
    else if ( size )
        size |= (uint64_t)~0 << 32;
    pci_conf_write32(sbdf, pos, bar);
    size = -size;

    if ( paddr )
        *paddr = (bar & mask) | ((uint64_t)hi << 32);
    *psize = size;

    return is64bits ? 2 : 1;
}

static int device_assigned(struct pci_dev *pdev)
{
    int rc = 0;

    /*
     * If the device exists and it is not owned by either the hardware
     * domain or dom_io then it must be assigned to a guest, or be
     * hidden (owned by dom_xen).
     */
    if ( pdev->domain != hardware_domain && pdev->domain != dom_io )
        rc = -EBUSY;

    return rc;
}

/* Caller should hold the pcidevs_lock */
static int pci_reassign_device(struct domain *prev_dom, struct domain *next_dom,
                               struct pci_dev *pdev, u32 flag)
{
    int rc = 0;
    ASSERT(prev_dom || next_dom);

    if ( !is_iommu_enabled(next_dom) )
        return -EINVAL;

    if ( !arch_iommu_use_permitted(next_dom) )
        return -EXDEV;

    /* Do not allow broken devices to be assigned to guests. */
    if ( pdev->broken && next_dom != hardware_domain && next_dom != dom_io )
        return -EBADF;

    if ( prev_dom )
    {
        write_lock(&prev_dom->pci_lock);
        vpci_deassign_device(pdev);
        write_unlock(&prev_dom->pci_lock);
    }

    rc = pdev_msix_assign(next_dom, pdev);
    if ( rc )
        goto done;

    pdev->fault.count = 0;

    if ( prev_dom && next_dom )
    {
        printk(XENLOG_INFO "PCI: Reassigning PCI device from %dd to %dd\n",
               prev_dom->domain_id, next_dom->domain_id);
    }
    else if ( prev_dom )
    {
        printk(XENLOG_INFO "PCI: Assigning PCI device to %dd\n", prev_dom->domain_id);
    }
    else if ( next_dom )
    {
        printk(XENLOG_INFO "PCI: Remove PCI device of %dd\n", next_dom->domain_id);
    }
    else
    {
        ASSERT_UNREACHABLE();
    }

    rc = iommu_reattach_context(prev_dom, next_dom, pci_to_dev(pdev), 0);

    if ( rc )
        goto done;

    if ( prev_dom )
    {
        write_lock(&prev_dom->pci_lock);
        list_del(&pdev->domain_list);
        write_unlock(&prev_dom->pci_lock);
    }

    pdev->domain = next_dom;

    if ( next_dom )
    {
        write_lock(&next_dom->pci_lock);
        list_add(&pdev->domain_list, &next_dom->pdev_list);

        rc = vpci_assign_device(pdev);
        write_unlock(&next_dom->pci_lock);
    }

 done:

    /* The device is assigned to dom_io so mark it as quarantined */
    if ( !rc && next_dom == dom_io )
        pdev->quarantine = true;

    return rc;
}

int pci_add_device(u16 seg, u8 bus, u8 devfn,
                   const struct pci_dev_info *info, nodeid_t node)
{
    struct pci_seg *pseg;
    struct pci_dev *pdev;
    unsigned int slot = PCI_SLOT(devfn), func = PCI_FUNC(devfn);
    const char *type;
    int ret;

    if ( !info )
        type = "device";
    else if ( info->is_virtfn )
        type = "virtual function";
    else if ( info->is_extfn )
        type = "extended function";
    else
        type = "device";

    ret = xsm_resource_plug_pci(XSM_PRIV, (seg << 16) | (bus << 8) | devfn);
    if ( ret )
        return ret;

    ret = -ENOMEM;

    pcidevs_lock();
    pseg = alloc_pseg(seg);
    if ( !pseg )
        goto out;
    pdev = alloc_pdev(pseg, bus, devfn);
    if ( !pdev )
        goto out;

    pdev->node = node;

    if ( info )
    {
        pdev->info = *info;
        if ( pdev->info.is_virtfn )
        {
            struct pci_dev *pf_pdev =
                pci_get_pdev(NULL, PCI_SBDF(seg, info->physfn.bus,
                                            info->physfn.devfn));

            if ( !pf_pdev )
            {
                printk(XENLOG_WARNING
                       "Attempted to add SR-IOV VF %pp without PF %pp\n",
                       &pdev->sbdf,
                       &PCI_SBDF(seg, info->physfn.bus, info->physfn.devfn));
                free_pdev(pseg, pdev);
                ret = -ENODEV;
                goto out;
            }

            if ( !pdev->pf_pdev )
            {
                pdev->pf_pdev = pf_pdev;

                /* VF inherits its 'is_extfn' from PF */
                pdev->info.is_extfn = pf_pdev->info.is_extfn;

                list_add(&pdev->vf_list, &pf_pdev->vf_list);
            }
        }
    }

    if ( !pdev->info.is_virtfn && !pdev->physfn.vf_rlen[0] )
    {
        unsigned int pos = pdev->sriov_pos;
        uint16_t ctrl = pci_conf_read16(pdev->sbdf, pos + PCI_SRIOV_CTRL);

        if ( !pos )
            /* Nothing */;
        else if ( !(ctrl & (PCI_SRIOV_CTRL_VFE | PCI_SRIOV_CTRL_MSE)) )
        {
            unsigned int i;

            BUILD_BUG_ON(ARRAY_SIZE(pdev->physfn.vf_rlen) !=
                                    PCI_SRIOV_NUM_BARS);

            for ( i = 0; i < PCI_SRIOV_NUM_BARS; )
            {
                unsigned int idx = pos + PCI_SRIOV_BAR + i * 4;
                uint32_t bar = pci_conf_read32(pdev->sbdf, idx);

                if ( (bar & PCI_BASE_ADDRESS_SPACE) ==
                     PCI_BASE_ADDRESS_SPACE_IO )
                {
                    printk(XENLOG_WARNING
                           "SR-IOV device %pp with vf BAR%u in IO space\n",
                           &pdev->sbdf, i);
                    ++i;
                    continue;
                }
                ret = pci_size_mem_bar(pdev->sbdf, idx, NULL,
                                       &pdev->physfn.vf_rlen[i],
                                       PCI_BAR_VF |
                                       ((i == PCI_SRIOV_NUM_BARS - 1) ?
                                        PCI_BAR_LAST : 0));
                ASSERT(ret);
                i += ret;
            }
        }
        else
            printk(XENLOG_WARNING "SR-IOV device %pp has its virtual"
                   " functions already enabled (%04x)\n", &pdev->sbdf, ctrl);
    }

    check_pdev(pdev);

    ret = 0;
    if ( !pdev->domain )
    {
        pdev->domain = hardware_domain;
        write_lock(&hardware_domain->pci_lock);
        list_add(&pdev->domain_list, &hardware_domain->pdev_list);

        /*
         * For devices not discovered by Xen during boot, add vPCI handlers
         * when Dom0 first informs Xen about such devices.
         */
        ret = vpci_assign_device(pdev);
        if ( ret )
        {
            list_del(&pdev->domain_list);
            write_unlock(&hardware_domain->pci_lock);
            pdev->domain = NULL;
            printk(XENLOG_ERR "Setup of vPCI failed: %d\n", ret);
            goto out;
        }
        write_unlock(&hardware_domain->pci_lock);
        ret = iommu_add_device(pdev);
        if ( ret )
        {
            write_lock(&hardware_domain->pci_lock);
            vpci_deassign_device(pdev);
            list_del(&pdev->domain_list);
            write_unlock(&hardware_domain->pci_lock);
            pdev->domain = NULL;
            goto out;
        }
    }
    else
        ret = iommu_add_device(pdev);

    pci_enable_acs(pdev);

out:
    pcidevs_unlock();
    if ( !ret )
    {
        printk(XENLOG_DEBUG "PCI add %s %pp\n", type, &pdev->sbdf);
        while ( pdev->phantom_stride )
        {
            func += pdev->phantom_stride;
            if ( PCI_SLOT(func) )
                break;
            printk(XENLOG_DEBUG "PCI phantom %pp\n",
                   &PCI_SBDF(seg, bus, slot, func));
        }
    }
    return ret;
}

int pci_remove_device(u16 seg, u8 bus, u8 devfn)
{
    struct pci_seg *pseg = get_pseg(seg);
    struct pci_dev *pdev;
    int ret;

    ret = xsm_resource_unplug_pci(XSM_PRIV, (seg << 16) | (bus << 8) | devfn);
    if ( ret )
        return ret;

    ret = -ENODEV;

    if ( !pseg )
        return -ENODEV;

    pcidevs_lock();
    list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
        if ( pdev->bus == bus && pdev->devfn == devfn )
        {
            if ( !pdev->info.is_virtfn && !list_empty(&pdev->vf_list) )
            {
                struct pci_dev *vf_pdev;

                /*
                 * Linux Dom0 has been observed to not respect an error code
                 * returned from PHYSDEVOP_pci_device_remove. Mark VFs and PF
                 * broken.
                 */
                list_for_each_entry(vf_pdev, &pdev->vf_list, vf_list)
                    vf_pdev->broken = true;

                pdev->broken = true;

                printk(XENLOG_WARNING
                       "Attempted to remove PCI SR-IOV PF %pp with VFs still present\n",
                       &pdev->sbdf);

                ret = -EBUSY;
                break;
            }

            if ( pdev->domain )
            {
                write_lock(&pdev->domain->pci_lock);
                vpci_deassign_device(pdev);
                list_del(&pdev->domain_list);
                write_unlock(&pdev->domain->pci_lock);
            }
            pci_cleanup_msi(pdev);
            ret = iommu_remove_device(pdev);
            printk(XENLOG_DEBUG "PCI remove device %pp\n", &pdev->sbdf);
            free_pdev(pseg, pdev);
            break;
        }

    pcidevs_unlock();
    return ret;
}

int pci_release_devices(struct domain *d)
{
    int combined_ret;
    LIST_HEAD(failed_pdevs);

    pcidevs_lock();

    combined_ret = arch_pci_clean_pirqs(d);
    if ( combined_ret )
    {
        pcidevs_unlock();
        return combined_ret;
    }

    write_lock(&d->pci_lock);

    while ( !list_empty(&d->pdev_list) )
    {
        struct pci_dev *pdev = list_first_entry(&d->pdev_list,
                                                struct pci_dev,
                                                domain_list);
        int ret;

        write_unlock(&d->pci_lock);
        ret = pci_reassign_device(d, dom_io, pdev, 0);
        write_lock(&d->pci_lock);
        if ( ret )
        {
            const struct pci_dev *tmp;

            /*
             * We need to check if deassign_device() left our pdev in
             * domain's list. As we dropped the lock, we can't be sure
             * that list wasn't permutated in some random way, so we
             * need to traverse the whole list.
             */
            for_each_pdev ( d, tmp )
            {
                if ( tmp == pdev )
                {
                    list_move_tail(&pdev->domain_list, &failed_pdevs);
                    break;
                }
            }

            combined_ret = combined_ret ?: ret;
        }
    }

    list_splice(&failed_pdevs, &d->pdev_list);
    write_unlock(&d->pci_lock);
    pcidevs_unlock();

    return combined_ret;
}

#define PCI_CLASS_BRIDGE_HOST    0x0600
#define PCI_CLASS_BRIDGE_PCI     0x0604

enum pdev_type pdev_type(u16 seg, u8 bus, u8 devfn)
{
    u16 class_device, creg;
    u8 d = PCI_SLOT(devfn), f = PCI_FUNC(devfn);
    unsigned int pos = pci_find_cap_offset(PCI_SBDF(seg, bus, devfn),
                                           PCI_CAP_ID_EXP);

    class_device = pci_conf_read16(PCI_SBDF(seg, bus, d, f), PCI_CLASS_DEVICE);
    switch ( class_device )
    {
    case PCI_CLASS_BRIDGE_PCI:
        if ( !pos )
            return DEV_TYPE_LEGACY_PCI_BRIDGE;
        creg = pci_conf_read16(PCI_SBDF(seg, bus, d, f), pos + PCI_EXP_FLAGS);
        switch ( (creg & PCI_EXP_FLAGS_TYPE) >> 4 )
        {
        case PCI_EXP_TYPE_PCI_BRIDGE:
            return DEV_TYPE_PCIe2PCI_BRIDGE;
        case PCI_EXP_TYPE_PCIE_BRIDGE:
            return DEV_TYPE_PCI2PCIe_BRIDGE;
        }
        return DEV_TYPE_PCIe_BRIDGE;
    case PCI_CLASS_BRIDGE_HOST:
        return DEV_TYPE_PCI_HOST_BRIDGE;

    case 0xffff:
        return DEV_TYPE_PCI_UNKNOWN;
    }

    /* NB: treat legacy pre PCI 2.0 devices (class_device == 0) as endpoints. */
    return pos ? DEV_TYPE_PCIe_ENDPOINT : DEV_TYPE_PCI;
}

/*
 * find the upstream PCIe-to-PCI/PCIX bridge or PCI legacy bridge
 * return 0: the device is integrated PCI device or PCIe
 * return 1: find PCIe-to-PCI/PCIX bridge or PCI legacy bridge
 * return -1: fail
 */
int find_upstream_bridge(u16 seg, u8 *bus, u8 *devfn, u8 *secbus)
{
    struct pci_seg *pseg = get_pseg(seg);
    int ret = 1;
    unsigned long flags;
    unsigned int cnt = 0;

    if ( *bus == 0 )
        return 0;

    if ( !pseg )
        return -1;

    if ( !pseg->bus2bridge[*bus].map )
        return 0;

    spin_lock_irqsave(&pseg->bus2bridge_lock, flags);
    while ( pseg->bus2bridge[*bus].map )
    {
        *secbus = *bus;
        *devfn = pseg->bus2bridge[*bus].devfn;
        *bus = pseg->bus2bridge[*bus].bus;
        if ( cnt++ >= MAX_BUSES )
        {
            ret = -1;
            goto out;
        }
    }

out:
    spin_unlock_irqrestore(&pseg->bus2bridge_lock, flags);
    return ret;
}

bool __init pci_device_detect(u16 seg, u8 bus, u8 dev, u8 func)
{
    u32 vendor;

    vendor = pci_conf_read32(PCI_SBDF(seg, bus, dev, func), PCI_VENDOR_ID);
    /* some broken boards return 0 or ~0 if a slot is empty: */
    if ( (vendor == 0xffffffffU) || (vendor == 0x00000000U) ||
         (vendor == 0x0000ffffU) || (vendor == 0xffff0000U) )
        return 0;
    return 1;
}

void pci_check_disable_device(u16 seg, u8 bus, u8 devfn)
{
    struct pci_dev *pdev;
    s_time_t now = NOW();
    u16 cword;

    pcidevs_lock();
    pdev = pci_get_real_pdev(PCI_SBDF(seg, bus, devfn));
    if ( pdev )
    {
        if ( now < pdev->fault.time ||
             now - pdev->fault.time > MILLISECS(10) )
            pdev->fault.count >>= 1;
        pdev->fault.time = now;
        if ( ++pdev->fault.count < PT_FAULT_THRESHOLD )
            pdev = NULL;
    }
    pcidevs_unlock();

    if ( !pdev )
        return;

    /* Tell the device to stop DMAing; we can't rely on the guest to
     * control it for us. */
    cword = pci_conf_read16(pdev->sbdf, PCI_COMMAND);
    pci_conf_write16(pdev->sbdf, PCI_COMMAND, cword & ~PCI_COMMAND_MASTER);
}

static void quirk_dma_func_phantom(pci_sbdf_t sbdf)
{
    struct phantom_dev phantom = {
        .seg = sbdf.seg,
        .bus = sbdf.bus,
        .slot = sbdf.devfn,
        .stride = 1,
    };

    phantom_devs[nr_phantom_devs++] = phantom;
}

static void quirk_scan_pci_device(pci_sbdf_t sbdf)
{
    unsigned int device, vendor = pci_conf_read16(sbdf, PCI_VENDOR_ID);

    switch ( vendor )
    {
    case 0x1b4b: /* Marvell */
    case 0x197B: /* JMICRON */
    case 0x1103: /* TTI */
        break;
    default:
        return;
    }

    device = pci_conf_read16(sbdf, PCI_DEVICE_ID);

    switch ( vendor )
    {
    case 0x1b4b: /* Marvell */
        switch ( device )
        {
        case 0x9120: /* 88SE9123 based controllers */
        case 0x9123:
        case 0x9130:
        case 0x9172:
        case 0x917a:
        case 0x91a0:
        case 0x9230:
            quirk_dma_func_phantom(sbdf);
            break;
        }
        break;

    case 0x197B: /* JMICRON */
        if ( device == 0x2393 ) /* JMB388 ESD */
            quirk_dma_func_phantom(sbdf);
        break;

    case 0x1103: /* TTI */
        if ( device == 0x0642 )
            quirk_dma_func_phantom(sbdf);
        break;
    }
}

/*
 * scan pci devices to add all existed PCI devices to alldevs_list,
 * and setup pci hierarchy in array bus2bridge.
 */
static int __init cf_check _scan_pci_devices(struct pci_seg *pseg, void *arg)
{
    struct pci_dev *pdev;
    int bus, dev, func;

    for ( bus = 0; bus < 256; bus++ )
    {
        for ( dev = 0; dev < 32; dev++ )
        {
            for ( func = 0; func < 8; func++ )
            {
                if ( !pci_device_detect(pseg->nr, bus, dev, func) )
                {
                    if ( !func )
                        break;
                    continue;
                }

                quirk_scan_pci_device(PCI_SBDF(pseg->nr, bus, dev, func));

                pdev = alloc_pdev(pseg, bus, PCI_DEVFN(dev, func));
                if ( !pdev )
                {
                    printk(XENLOG_WARNING "%pp: alloc_pdev failed\n",
                           &PCI_SBDF(pseg->nr, bus, dev, func));
                    return -ENOMEM;
                }

                if ( !func && !(pci_conf_read8(PCI_SBDF(pseg->nr, bus, dev,
                                                        func),
                                               PCI_HEADER_TYPE) & 0x80) )
                    break;
            }
        }
    }

    return 0;
}

int __init scan_pci_devices(void)
{
    int ret;

    pcidevs_lock();
    ret = pci_segments_iterate(_scan_pci_devices, NULL);
    pcidevs_unlock();

    return ret;
}

struct setup_hwdom {
    struct domain *d;
    int (*handler)(uint8_t devfn, struct pci_dev *pdev);
};

static void __hwdom_init setup_one_hwdom_device(const struct setup_hwdom *ctxt,
                                                struct pci_dev *pdev)
{
    int err;

    err = ctxt->handler(pdev->devfn, pdev);

    if ( err )
        goto done;

    write_lock(&ctxt->d->pci_lock);
    err = vpci_assign_device(pdev);
    write_unlock(&ctxt->d->pci_lock);

done:
    if ( err )
        printk(XENLOG_ERR "setup of vPCI for d%d failed: %d\n",
               ctxt->d->domain_id, err);
}

static int __hwdom_init cf_check _setup_hwdom_pci_devices(
    struct pci_seg *pseg, void *arg)
{
    struct setup_hwdom *ctxt = arg;
    int bus, devfn;

    for ( bus = 0; bus < 256; bus++ )
    {
        for ( devfn = 0; devfn < 256; devfn++ )
        {
            struct pci_dev *pdev = pci_get_pdev(NULL,
                                                PCI_SBDF(pseg->nr, bus, devfn));

            if ( !pdev )
                continue;

            if ( !pdev->domain )
            {
                pdev->domain = ctxt->d;
                write_lock(&ctxt->d->pci_lock);
                list_add(&pdev->domain_list, &ctxt->d->pdev_list);
                write_unlock(&ctxt->d->pci_lock);
                setup_one_hwdom_device(ctxt, pdev);
            }
            else if ( pdev->domain == dom_xen )
            {
                pdev->domain = ctxt->d;
                setup_one_hwdom_device(ctxt, pdev);
                pdev->domain = dom_xen;
            }
            else if ( pdev->domain != ctxt->d )
                printk(XENLOG_WARNING "Dom%d owning %pp?\n",
                       pdev->domain->domain_id, &pdev->sbdf);

            if ( iommu_verbose )
            {
                pcidevs_unlock();
                process_pending_softirqs();
                pcidevs_lock();
            }
        }

        if ( !iommu_verbose )
        {
            pcidevs_unlock();
            process_pending_softirqs();
            pcidevs_lock();
        }
    }

    return 0;
}

void __hwdom_init setup_hwdom_pci_devices(
    struct domain *d, int (*handler)(uint8_t devfn, struct pci_dev *pdev))
{
    struct setup_hwdom ctxt = { .d = d, .handler = handler };

    pcidevs_lock();
    pci_segments_iterate(_setup_hwdom_pci_devices, &ctxt);
    pcidevs_unlock();
}

/* APEI not supported on ARM yet. */
#if defined(CONFIG_ACPI) && defined(CONFIG_X86)
#include <acpi/acpi.h>
#include <acpi/apei.h>

static int hest_match_pci(const struct acpi_hest_aer_common *p,
                          const struct pci_dev *pdev)
{
    return ACPI_HEST_SEGMENT(p->bus) == pdev->seg &&
           ACPI_HEST_BUS(p->bus)     == pdev->bus &&
           p->device                 == PCI_SLOT(pdev->devfn) &&
           p->function               == PCI_FUNC(pdev->devfn);
}

static bool hest_match_type(const struct acpi_hest_header *hest_hdr,
                              const struct pci_dev *pdev)
{
    unsigned int pos = pci_find_cap_offset(pdev->sbdf, PCI_CAP_ID_EXP);
    u8 pcie = MASK_EXTR(pci_conf_read16(pdev->sbdf, pos + PCI_EXP_FLAGS),
                        PCI_EXP_FLAGS_TYPE);

    switch ( hest_hdr->type )
    {
    case ACPI_HEST_TYPE_AER_ROOT_PORT:
        return pcie == PCI_EXP_TYPE_ROOT_PORT;
    case ACPI_HEST_TYPE_AER_ENDPOINT:
        return pcie == PCI_EXP_TYPE_ENDPOINT;
    case ACPI_HEST_TYPE_AER_BRIDGE:
        return pci_conf_read16(pdev->sbdf, PCI_CLASS_DEVICE) ==
               PCI_CLASS_BRIDGE_PCI;
    }

    return 0;
}

struct aer_hest_parse_info {
    const struct pci_dev *pdev;
    bool firmware_first;
};

static bool hest_source_is_pcie_aer(const struct acpi_hest_header *hest_hdr)
{
    if ( hest_hdr->type == ACPI_HEST_TYPE_AER_ROOT_PORT ||
         hest_hdr->type == ACPI_HEST_TYPE_AER_ENDPOINT ||
         hest_hdr->type == ACPI_HEST_TYPE_AER_BRIDGE )
        return 1;
    return 0;
}

static int cf_check aer_hest_parse(
    const struct acpi_hest_header *hest_hdr, void *data)
{
    struct aer_hest_parse_info *info = data;
    const struct acpi_hest_aer_common *p;
    bool ff;

    if ( !hest_source_is_pcie_aer(hest_hdr) )
        return 0;

    p = (const struct acpi_hest_aer_common *)(hest_hdr + 1);
    ff = !!(p->flags & ACPI_HEST_FIRMWARE_FIRST);

    /*
     * If no specific device is supplied, determine whether
     * FIRMWARE_FIRST is set for *any* PCIe device.
     */
    if ( !info->pdev )
    {
        info->firmware_first |= ff;
        return 0;
    }

    /* Otherwise, check the specific device */
    if ( p->flags & ACPI_HEST_GLOBAL ?
         hest_match_type(hest_hdr, info->pdev) :
         hest_match_pci(p, info->pdev) )
    {
        info->firmware_first = ff;
        return 1;
    }

    return 0;
}

bool pcie_aer_get_firmware_first(const struct pci_dev *pdev)
{
    struct aer_hest_parse_info info = { .pdev = pdev };

    return pci_find_cap_offset(pdev->sbdf, PCI_CAP_ID_EXP) &&
           apei_hest_parse(aer_hest_parse, &info) >= 0 &&
           info.firmware_first;
}
#endif

static int cf_check _dump_pci_devices(struct pci_seg *pseg, void *arg)
{
    struct pci_dev *pdev;

    printk("==== segment %04x ====\n", pseg->nr);

    list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
    {
        printk("%pp - ", &pdev->sbdf);
        printk("%pd", pdev->domain);
        printk(" - node %-3d", (pdev->node != NUMA_NO_NODE) ? pdev->node : -1);
        pdev_dump_msi(pdev);
        printk("\n");
    }

    return 0;
}

static void cf_check dump_pci_devices(unsigned char ch)
{
    printk("==== PCI devices ====\n");
    pcidevs_lock();
    pci_segments_iterate(_dump_pci_devices, NULL);
    pcidevs_unlock();
}

static int __init cf_check setup_dump_pcidevs(void)
{
    register_keyhandler('Q', dump_pci_devices, "dump PCI devices", 1);
    return 0;
}
__initcall(setup_dump_pcidevs);

static int iommu_add_device(struct pci_dev *pdev)
{
    const struct domain_iommu *hd;

    if ( !pdev->domain )
        return -EINVAL;

    ASSERT(pcidevs_locked());

    hd = dom_iommu(pdev->domain);
    if ( !is_iommu_enabled(pdev->domain) )
        return 0;

    return iommu_attach_context(pdev->domain, pci_to_dev(pdev), 0);
}

static int iommu_remove_device(struct pci_dev *pdev)
{
    if ( !pdev->domain )
        return -EINVAL;

    if ( !is_iommu_enabled(pdev->domain) )
        return 0;

    return iommu_detach_context(pdev->domain, pdev);
}

static int iommu_get_device_group(
    struct domain *d, u16 seg, u8 bus, u8 devfn,
    XEN_GUEST_HANDLE_64(uint32) buf, int max_sdevs)
{
    const struct domain_iommu *hd = dom_iommu(d);
    struct pci_dev *pdev;
    int group_id, sdev_id;
    u32 bdf;
    int i = 0;
    const struct iommu_ops *ops = hd->platform_ops;

    if ( !is_iommu_enabled(d) || !ops->get_device_group_id )
        return 0;

    group_id = iommu_call(ops, get_device_group_id, seg, bus, devfn);
    if ( group_id < 0 )
        return group_id;

    pcidevs_lock();
    for_each_pdev( d, pdev )
    {
        unsigned int b = pdev->bus;
        unsigned int df = pdev->devfn;

        if ( (pdev->seg != seg) || ((b == bus) && (df == devfn)) )
            continue;

        if ( xsm_get_device_group(XSM_HOOK, (seg << 16) | (b << 8) | df) )
            continue;

        sdev_id = iommu_call(ops, get_device_group_id, seg, b, df);
        if ( sdev_id < 0 )
        {
            pcidevs_unlock();
            return sdev_id;
        }

        if ( (sdev_id == group_id) && (i < max_sdevs) )
        {
            bdf = (b << 16) | (df << 8);

            if ( unlikely(copy_to_guest_offset(buf, i, &bdf, 1)) )
            {
                pcidevs_unlock();
                return -EFAULT;
            }
            i++;
        }
    }

    pcidevs_unlock();

    return i;
}

void iommu_dev_iotlb_flush_timeout(struct domain *d, struct pci_dev *pdev)
{
    pcidevs_lock();

    disable_ats_device(pdev);

    ASSERT(pdev->domain);
    if ( d != pdev->domain )
    {
        pcidevs_unlock();
        return;
    }

    pdev->broken = true;

    if ( !d->is_shutting_down && printk_ratelimit() )
        printk(XENLOG_ERR "dom%d: ATS device %pp flush failed\n",
               d->domain_id, &pdev->sbdf);
    if ( !is_hardware_domain(d) )
        domain_crash(d);

    pcidevs_unlock();
}

int iommu_do_pci_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    u16 seg;
    u8 bus, devfn;
    int ret = 0;
    uint32_t machine_sbdf;
    struct pci_dev *pdev;

    switch ( domctl->cmd )
    {
        unsigned int flags;

    case XEN_DOMCTL_get_device_group:
    {
        u32 max_sdevs;
        XEN_GUEST_HANDLE_64(uint32) sdevs;

        ret = xsm_get_device_group(XSM_HOOK, domctl->u.get_device_group.machine_sbdf);
        if ( ret )
            break;

        seg = domctl->u.get_device_group.machine_sbdf >> 16;
        bus = PCI_BUS(domctl->u.get_device_group.machine_sbdf);
        devfn = PCI_DEVFN(domctl->u.get_device_group.machine_sbdf);
        max_sdevs = domctl->u.get_device_group.max_sdevs;
        sdevs = domctl->u.get_device_group.sdev_array;

        ret = iommu_get_device_group(d, seg, bus, devfn, sdevs, max_sdevs);
        if ( ret < 0 )
        {
            dprintk(XENLOG_ERR, "iommu_get_device_group() failed: %d\n", ret);
            domctl->u.get_device_group.num_sdevs = 0;
        }
        else
        {
            domctl->u.get_device_group.num_sdevs = ret;
            ret = 0;
        }
        if ( __copy_field_to_guest(u_domctl, domctl, u.get_device_group) )
            ret = -EFAULT;
    }
    break;

    case XEN_DOMCTL_assign_device:
        ASSERT(d);
        /* fall through */
    case XEN_DOMCTL_test_assign_device:
        /* Don't support self-assignment of devices. */
        if ( d == current->domain )
        {
            ret = -EINVAL;
            break;
        }

        ret = -ENODEV;
        if ( domctl->u.assign_device.dev != XEN_DOMCTL_DEV_PCI )
            break;

        ret = -EINVAL;
        flags = domctl->u.assign_device.flags;
        if ( domctl->cmd == XEN_DOMCTL_assign_device
             ? d->is_dying || (flags & ~XEN_DOMCTL_DEV_RDM_RELAXED)
             : flags )
            break;

        machine_sbdf = domctl->u.assign_device.u.pci.machine_sbdf;

        ret = xsm_assign_device(XSM_HOOK, d, machine_sbdf);
        if ( ret )
            break;

        seg = machine_sbdf >> 16;
        bus = PCI_BUS(machine_sbdf);
        devfn = PCI_DEVFN(machine_sbdf);

        pcidevs_lock();
        pdev = pci_get_pdev(NULL, PCI_SBDF(seg, bus, devfn));

        if ( !pdev )
        {
            printk(XENLOG_G_INFO "%pp doesn't exist", &PCI_SBDF(seg, bus, devfn));
            break;
        }

        ret = device_assigned(pdev);
        if ( domctl->cmd == XEN_DOMCTL_test_assign_device )
        {
            if ( ret )
            {
                printk(XENLOG_G_INFO "%pp already assigned, or non-existent\n",
                       &PCI_SBDF(seg, bus, devfn));
                ret = -EINVAL;
            }
        }
        else if ( !ret )
            ret = pci_reassign_device(pdev->domain, d, pdev, flags);
        pcidevs_unlock();
        if ( ret == -ERESTART )
            ret = hypercall_create_continuation(__HYPERVISOR_domctl,
                                                "h", u_domctl);
        break;

    case XEN_DOMCTL_deassign_device:
        /* Don't support self-deassignment of devices. */
        if ( d == current->domain )
        {
            ret = -EINVAL;
            break;
        }

        ret = -ENODEV;
        if ( domctl->u.assign_device.dev != XEN_DOMCTL_DEV_PCI )
            break;

        ret = -EINVAL;
        if ( domctl->u.assign_device.flags )
            break;

        machine_sbdf = domctl->u.assign_device.u.pci.machine_sbdf;

        ret = xsm_deassign_device(XSM_HOOK, d, machine_sbdf);
        if ( ret )
            break;

        seg = machine_sbdf >> 16;
        bus = PCI_BUS(machine_sbdf);
        devfn = PCI_DEVFN(machine_sbdf);

        pcidevs_lock();
        pdev = pci_get_pdev(d, PCI_SBDF(seg, bus, devfn));

        if ( pdev )
        {
            struct domain *target = hardware_domain;

            if ( (pdev->quarantine || iommu_quarantine) && pdev->domain != dom_io )
                target = dom_io;

            ret = pci_reassign_device(d, target, pdev, 0);
        }
        else
            ret = -ENODEV;

        pcidevs_unlock();
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

struct segment_iter {
    int (*handler)(struct pci_dev *pdev, void *arg);
    void *arg;
    int rc;
};

static int cf_check iterate_all(struct pci_seg *pseg, void *arg)
{
    struct segment_iter *iter = arg;
    struct pci_dev *pdev;

    list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
    {
        int rc = iter->handler(pdev, iter->arg);

        if ( !iter->rc )
            iter->rc = rc;
    }

    return 0;
}

/*
 * Iterate without locking or preemption over all PCI devices known by Xen.
 * Can be called with interrupts disabled.
 */
int pci_iterate_devices(int (*handler)(struct pci_dev *pdev, void *arg),
                        void *arg)
{
    struct segment_iter iter = {
        .handler = handler,
        .arg = arg,
    };

    return pci_segments_iterate(iterate_all, &iter) ?: iter.rc;
}

struct pci_dev_config {
    uint16_t start:12;
    uint16_t version:4;
    uint16_t id;
};

static int add_write_accessible(struct rangeset *config_writable,
                                uint16_t start, uint16_t len)
{
    /* some sanity check */
    if ( start >= 4096 || start + len > 4096 )
        return 0;

    return rangeset_add_range(config_writable, start, start + len - 1);
}

static int add_accesses(struct pci_dev *pdev,
                        struct pci_dev_config *configs, uint16_t num_configs)
{
    int rc;
    struct rangeset *config_writable = rangeset_new(NULL, "config writable", 0);

    if ( !config_writable )
        return -ENOMEM;

#define add_write_accessible(start, len) do { \
        rc = add_write_accessible(config_writable, start, len); \
        if ( rc < 0 ) goto fail; \
    } while(0)

    /* Base ones (offsets 0-0x40) */
    add_write_accessible(PCI_COMMAND, 2);
    add_write_accessible(PCI_STATUS, 2);

    /* Scan various configurations */
    for ( unsigned int i = 0; i < num_configs; ++i )
    {
        const struct pci_dev_config *const config = &configs[i];

        if ( config->start < 0x100 && config->id == PCI_CAP_ID_MSIX )
            add_write_accessible(config->start + PCI_MSIX_FLAGS, 2);
        if ( config->start < 0x100 && config->id == PCI_CAP_ID_PM )
            add_write_accessible(config->start + PCI_PM_CTRL, 2);
        if ( config->start < 0x100 && config->id == PCI_CAP_ID_MSI )
            add_write_accessible(config->start + PCI_MSI_FLAGS, 2);
    }

    /* Link to the device */
    pdev->config_writable = config_writable;
    return 0;

 fail:
    rangeset_destroy(config_writable);
    return rc;
}

static int pdev_config_writable_init(struct pci_dev *pdev)
{
    /*
     * Capabilities starts at a multiple of 4 bytes, use a bitmap to mark
     * already encountered starts.
     * We need to do this to avoid circular scanning, the order of the
     * capability offsets is not always increasing.
     */
    enum { NUM_CAP_STARTS = 4096 / 4 };
    struct pci_dev_config *configs = NULL;
    uint16_t num_configs;
    DECLARE_BITMAP(cap_starts, NUM_CAP_STARTS);
    uint16_t status;
    uint32_t header;
    int rc;

    bitmap_zero(cap_starts, NUM_CAP_STARTS);

    /* Scan all capabilities */
    status = pci_conf_read16(pdev->sbdf, PCI_STATUS);
    if ( (status & PCI_STATUS_CAP_LIST) != 0 )
    {
        for ( uint8_t pos = PCI_CAPABILITY_LIST; ; pos += PCI_CAP_LIST_NEXT )
        {
            uint8_t id;

            pos = pci_conf_read8(pdev->sbdf, pos);
            if ( pos < 0x40 )
                break;

            pos &= ~3;
            /* avoids recursion */
            if ( test_bit(pos / 4, cap_starts) )
                break;
            set_bit(pos / 4, cap_starts);

            id = pci_conf_read8(pdev->sbdf, pos + PCI_CAP_LIST_ID);

            if ( id == 0xff )
                break;
        }
    }

    /* Scan all extended capabilities */
    header = pci_conf_read32(pdev->sbdf, 0x100);

    /*
     * If we have no capabilities, this is indicated by cap ID,
     * cap version and next pointer all being 0.
     */
    if ( header != 0 && header != -1 )
    {
        unsigned int pos = 0x100;

        for ( ; ; )
        {
            /* avoids recursion */
            if ( test_bit(pos / 4, cap_starts) )
                break;
            set_bit(pos / 4, cap_starts);

            pos = PCI_EXT_CAP_NEXT(header);
            if ( pos < 0x100 )
                break;
            header = pci_conf_read32(pdev->sbdf, pos);
        }
    }

    num_configs = bitmap_weight(cap_starts, NUM_CAP_STARTS);
    configs = xzalloc_array(struct pci_dev_config, num_configs);
    if ( !configs )
        return -ENOMEM;

    for ( unsigned int start = find_first_bit(cap_starts, NUM_CAP_STARTS),
          i = 0;
          start < NUM_CAP_STARTS;
          start = find_next_bit(cap_starts, NUM_CAP_STARTS, start + 1) )
    {
        const unsigned int pos = start * 4;
        struct pci_dev_config *const config = &configs[i++];

        config->start = pos;
        if ( pos < 0x100 )
        {
            uint8_t id = pci_conf_read8(pdev->sbdf, pos + PCI_CAP_LIST_ID);

            config->version = 0;
            config->id = id;
        }
        else
        {
            uint32_t header = pci_conf_read32(pdev->sbdf, pos);

            config->version = PCI_EXT_CAP_VER(header);
            config->id = PCI_EXT_CAP_ID(header);
        }
    }

    rc = add_accesses(pdev, configs, num_configs);
    xfree(configs);

    return min(rc, 0);
}

bool pdev_has_write_access(const struct pci_dev *pdev,
                           uint32_t pos, uint8_t size)
{
    ASSERT(pdev->config_writable);

    if ( pos >= 4096 )
        return false;

    /* Search entry in writable table */
    return rangeset_contains_range(pdev->config_writable, pos, pos + size - 1);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
