#include <xen/init.h>
#include <xen/pci.h>
#include <xen/list.h>
#include <xen/tasklet.h>
#include <xen/pci_ids.h>
#include <xen/delay.h>
#include <xen/timer.h>
#include <xen/wait.h>
#include <xen/smp.h>
#include <asm/msi.h>
#include <asm/system.h>
#include <asm/psp-sev.h>

/*
TODO:
-  GLOBAL:
     - add command line params for tunables
 - INTERRUPT MODE:
    - CET shadow stack: adapt #CP handler???
    - Serialization: must be done by the client? adapt spinlock?
 */

#define PSP_CAPABILITY_SEV                      (1 << 0)
#define PSP_CAPABILITY_TEE                      (1 << 1)
#define PSP_CAPABILITY_PSP_SECURITY_REPORTING   (1 << 7)
#define PSP_CAPABILITY_PSP_SECURITY_OFFSET      8

#define PSP_INTSTS_CMD_COMPLETE       (1 << 1)

#define SEV_CMDRESP_CMD_MASK          0x7ff0000
#define SEV_CMDRESP_CMD_SHIFT         16
#define SEV_CMDRESP_CMD(cmd)          ((cmd) << SEV_CMDRESP_CMD_SHIFT)
#define SEV_CMDRESP_STS_MASK          0xffff
#define SEV_CMDRESP_STS(x)            ((x) & SEV_CMDRESP_STS_MASK)
#define SEV_CMDRESP_RESP              (1 << 31)
#define SEV_CMDRESP_IOC               (1 << 0)

#define ASP_CMD_BUFF_SIZE    0x1000
#define SEV_FW_BLOB_MAX_SIZE 0x4000

/*
 * SEV platform state
 */
enum sev_state {
        SEV_STATE_UNINIT                = 0x0,
        SEV_STATE_INIT                  = 0x1,
        SEV_STATE_WORKING               = 0x2,
        SEV_STATE_MAX
};

struct sev_vdata {
    const unsigned int cmdresp_reg;
    const unsigned int cmdbuff_addr_lo_reg;
    const unsigned int cmdbuff_addr_hi_reg;
};

struct psp_vdata {
    const unsigned short   base_offset;
    const struct sev_vdata *sev;
    const unsigned int feature_reg;
    const unsigned int inten_reg;
    const unsigned int intsts_reg;
    const char* name;
};

static struct sev_vdata sevv1 = {
    .cmdresp_reg         = 0x10580,     /* C2PMSG_32 */
    .cmdbuff_addr_lo_reg = 0x105e0,     /* C2PMSG_56 */
    .cmdbuff_addr_hi_reg = 0x105e4,     /* C2PMSG_57 */
};

static struct sev_vdata sevv2 = {
    .cmdresp_reg         = 0x10980,     /* C2PMSG_32 */
    .cmdbuff_addr_lo_reg = 0x109e0,     /* C2PMSG_56 */
    .cmdbuff_addr_hi_reg = 0x109e4,     /* C2PMSG_57 */
};

static struct psp_vdata pspv1 = {
    .base_offset = PCI_BASE_ADDRESS_2,
    .sev         = &sevv1,
    .feature_reg = 0x105fc,     /* C2PMSG_63 */
    .inten_reg   = 0x10610,     /* P2CMSG_INTEN */
    .intsts_reg  = 0x10614,     /* P2CMSG_INTSTS */
    .name = "pspv1",
};

static struct psp_vdata pspv2 = {
    .base_offset = PCI_BASE_ADDRESS_2,
    .sev         = &sevv2,
    .feature_reg = 0x109fc,     /* C2PMSG_63 */
    .inten_reg   = 0x10690,     /* P2CMSG_INTEN */
    .intsts_reg  = 0x10694,     /* P2CMSG_INTSTS */
    .name = "pspv2",
};

static struct psp_vdata pspv4 = {
    .base_offset = PCI_BASE_ADDRESS_2,
    .sev         = &sevv2,
    .feature_reg = 0x109fc,     /* C2PMSG_63 */
    .inten_reg   = 0x10690,     /* P2CMSG_INTEN */
    .intsts_reg  = 0x10694,     /* P2CMSG_INTSTS */
    .name = "pspv4",
};

static struct psp_vdata pspv6 = {
    .base_offset =  PCI_BASE_ADDRESS_2,
    .sev         = &sevv2,
    .feature_reg = 0x109fc,     /* C2PMSG_63 */
    .inten_reg   = 0x10510,     /* P2CMSG_INTEN */
    .intsts_reg  = 0x10514,     /* P2CMSG_INTSTS */
    .name = "pspv6",
};

struct amd_sp_dev
{
    struct list_head list;
    struct pci_dev   *pdev;
    struct  psp_vdata *vdata;
    void    *io_base;
    paddr_t io_pbase;
    size_t  io_size;
    int     irq;
    int     state;
    void* cmd_buff;
    uint32_t cbuff_pa_low;
    uint32_t cbuff_pa_high;
    unsigned int capability;
    uint8_t api_major;
    uint8_t api_minor;
    uint8_t build;
    int     intr_rcvd;
    int     cmd_timeout;
    struct timer cmd_timer;
    struct waitqueue_head cmd_in_progress;
};

LIST_HEAD(amd_sp_units);
#define for_each_sp_unit(sp) \
    list_for_each_entry(sp, &amd_sp_units, list)

static spinlock_t _sp_cmd_lock = SPIN_LOCK_UNLOCKED;

static struct amd_sp_dev *amd_sp_master;

static void do_sp_irq(void *data);
static DECLARE_SOFTIRQ_TASKLET(sp_irq_tasklet, do_sp_irq, NULL);

static bool force_sync = false;
static unsigned int asp_timeout_val = 30000;
static unsigned long long asp_sync_delay = 100ULL;
static int asp_sync_tries = 10;

static void sp_cmd_lock(void)
{
    spin_lock(&_sp_cmd_lock);
}

static void sp_cmd_unlock(void)
{
    spin_unlock(&_sp_cmd_lock);
}

static int sev_cmd_buffer_len(int cmd)
{
    switch (cmd) {
        case SEV_CMD_INIT:                      return sizeof(struct sev_data_init);
        case SEV_CMD_INIT_EX:                   return sizeof(struct sev_data_init_ex);
        case SEV_CMD_PLATFORM_STATUS:           return sizeof(struct sev_user_data_status);
        case SEV_CMD_PEK_CSR:                   return sizeof(struct sev_data_pek_csr);
        case SEV_CMD_PEK_CERT_IMPORT:           return sizeof(struct sev_data_pek_cert_import);
        case SEV_CMD_PDH_CERT_EXPORT:           return sizeof(struct sev_data_pdh_cert_export);
        case SEV_CMD_LAUNCH_START:              return sizeof(struct sev_data_launch_start);
        case SEV_CMD_LAUNCH_UPDATE_DATA:        return sizeof(struct sev_data_launch_update_data);
        case SEV_CMD_LAUNCH_UPDATE_VMSA:        return sizeof(struct sev_data_launch_update_vmsa);
        case SEV_CMD_LAUNCH_FINISH:             return sizeof(struct sev_data_launch_finish);
        case SEV_CMD_LAUNCH_MEASURE:            return sizeof(struct sev_data_launch_measure);
        case SEV_CMD_ACTIVATE:                  return sizeof(struct sev_data_activate);
        case SEV_CMD_DEACTIVATE:                return sizeof(struct sev_data_deactivate);
        case SEV_CMD_DECOMMISSION:              return sizeof(struct sev_data_decommission);
        case SEV_CMD_GUEST_STATUS:              return sizeof(struct sev_data_guest_status);
        case SEV_CMD_DBG_DECRYPT:               return sizeof(struct sev_data_dbg);
        case SEV_CMD_DBG_ENCRYPT:               return sizeof(struct sev_data_dbg);
        case SEV_CMD_SEND_START:                return sizeof(struct sev_data_send_start);
        case SEV_CMD_SEND_UPDATE_DATA:          return sizeof(struct sev_data_send_update_data);
        case SEV_CMD_SEND_UPDATE_VMSA:          return sizeof(struct sev_data_send_update_vmsa);
        case SEV_CMD_SEND_FINISH:               return sizeof(struct sev_data_send_finish);
        case SEV_CMD_RECEIVE_START:             return sizeof(struct sev_data_receive_start);
        case SEV_CMD_RECEIVE_FINISH:            return sizeof(struct sev_data_receive_finish);
        case SEV_CMD_RECEIVE_UPDATE_DATA:       return sizeof(struct sev_data_receive_update_data);
        case SEV_CMD_RECEIVE_UPDATE_VMSA:       return sizeof(struct sev_data_receive_update_vmsa);
        case SEV_CMD_LAUNCH_UPDATE_SECRET:      return sizeof(struct sev_data_launch_secret);
        case SEV_CMD_DOWNLOAD_FIRMWARE:         return sizeof(struct sev_data_download_firmware);
        case SEV_CMD_GET_ID:                    return sizeof(struct sev_data_get_id);
        case SEV_CMD_ATTESTATION_REPORT:        return sizeof(struct sev_data_attestation_report);
        case SEV_CMD_SEND_CANCEL:               return sizeof(struct sev_data_send_cancel);
        default:                                return 0;
    }

    return 0;
}

static void invalidate_cache(void *unused)
{
    wbinvd();
}

int _sev_do_cmd(struct amd_sp_dev *sp, int cmd, void *data, int *psp_ret)
{
    unsigned int cbuff_pa_low, cbuff_pa_high, cmd_val;
    int buf_len, cmdresp, rc;


    buf_len = sev_cmd_buffer_len(cmd);


    if ( data )
        memcpy(sp->cmd_buff, data, buf_len);

    cbuff_pa_low  = data ? sp->cbuff_pa_low : 0;
    cbuff_pa_high = data ? sp->cbuff_pa_high : 0;

    writel(cbuff_pa_low, sp->io_base + sp->vdata->sev->cmdbuff_addr_lo_reg);
    writel(cbuff_pa_high, sp->io_base + sp->vdata->sev->cmdbuff_addr_hi_reg);

    cmd_val = SEV_CMDRESP_CMD(cmd) | SEV_CMDRESP_IOC;

    sp->cmd_timeout = 0;
    sp->intr_rcvd = 0;

    writel(cmd_val, sp->io_base + sp->vdata->sev->cmdresp_reg);

    set_timer(&sp->cmd_timer,  NOW() + MILLISECS(asp_timeout_val));

    /* FIXME: If the timer triggers here the device will be set offline */

    wait_event(sp->cmd_in_progress, sp->cmd_timeout || sp->intr_rcvd);

    stop_timer(&sp->cmd_timer);

    if ( sp->intr_rcvd )
    {
        cmdresp = readl(sp->io_base + sp->vdata->sev->cmdresp_reg);

	ASSERT(cmdresp & SEV_CMDRESP_RESP);

        rc = SEV_CMDRESP_STS(cmdresp) ? -EFAULT : 0;

	if ( rc && psp_ret )
            *psp_ret = SEV_CMDRESP_STS(cmdresp);

	if ( data && (!rc) )
	    memcpy(data, sp->cmd_buff, buf_len);
    }
    else
    {
        ASSERT(sp->cmd_timeout);

        sp->state = SEV_STATE_UNINIT;

        writel(0, sp->io_base + sp->vdata->inten_reg);

        rc = -EIO;
    }
    return rc;
}

static int _sev_do_cmd_sync(struct amd_sp_dev *sp, int cmd, void *data, int *psp_ret)
{
    unsigned int cbuff_pa_low, cbuff_pa_high, cmd_val;
    int buf_len, cmdresp, rc, i;

    buf_len = sev_cmd_buffer_len(cmd);

    if ( data )
        memcpy(sp->cmd_buff, data, buf_len);

    cbuff_pa_low  = data ? sp->cbuff_pa_low : 0;
    cbuff_pa_high = data ? sp->cbuff_pa_high : 0;

    writel(cbuff_pa_low, sp->io_base + sp->vdata->sev->cmdbuff_addr_lo_reg);
    writel(cbuff_pa_high, sp->io_base + sp->vdata->sev->cmdbuff_addr_hi_reg);

    cmd_val = SEV_CMDRESP_CMD(cmd);

    writel(cmd_val, sp->io_base + sp->vdata->sev->cmdresp_reg);

    for (rc = -EIO, i = asp_sync_tries; i; i-- )
    {

	mdelay(asp_sync_delay);

	cmdresp = readl(sp->io_base + sp->vdata->sev->cmdresp_reg);
	if ( cmdresp & SEV_CMDRESP_RESP )
	{
	    rc = 0;
	    break;
	}
    }

    if ( !rc && SEV_CMDRESP_STS(cmdresp) )
	rc = -EFAULT;

    if ( rc &&  psp_ret )
        *psp_ret = SEV_CMDRESP_STS(cmdresp);

    if ( data && (!rc) )
        memcpy(data, sp->cmd_buff, buf_len);

    return rc;
}

int sev_do_cmd(int cmd, void *data, int *psp_ret, bool poll)
{
    struct amd_sp_dev *sp  = amd_sp_master;
    int buf_len, rc;

    if ( !sp )
	return -ENODEV;

    if ( sp->state < SEV_STATE_INIT )
        return -ENODEV;

    if ( cmd >= SEV_CMD_MAX )
        return -EINVAL;

    buf_len = sev_cmd_buffer_len(cmd);

    if ( !data != !buf_len )
        return -EINVAL;

    if ( force_sync || poll )
    {
	sp_cmd_lock();
	rc = _sev_do_cmd_sync(sp, cmd, data, psp_ret);
	sp_cmd_unlock();
    }
    else
    {
	rc = _sev_do_cmd(sp, cmd, data, psp_ret);
    }

    return rc;
}

static void do_sp_cmd_timer(void *data)
{
    struct amd_sp_dev *sp = (struct amd_sp_dev*)data;

    sp->cmd_timeout = 1;
    wake_up_nr(&sp->cmd_in_progress, 1);
}

static void do_sp_irq(void *data)
{
    struct amd_sp_dev *sp;

    for_each_sp_unit(sp) {
	uint32_t cmdresp = readl(sp->io_base + sp->vdata->sev->cmdresp_reg);
	if ( cmdresp & SEV_CMDRESP_RESP )
	{
	    sp->intr_rcvd = 1;
	    wake_up_nr(&sp->cmd_in_progress, 1);
	}
    }
}

static void sp_interrupt_handler(int irq, void *dev_id)
{
    struct amd_sp_dev *sp = (struct amd_sp_dev*)dev_id;
    uint32_t status;

    status = readl(sp->io_base + sp->vdata->intsts_reg);
    writel(status, sp->io_base + sp->vdata->intsts_reg);

    if ( status & PSP_INTSTS_CMD_COMPLETE )
	    tasklet_schedule(&sp_irq_tasklet);
}

static int __init sp_get_capability(struct amd_sp_dev *sp)
{
    uint32_t val = readl(sp->io_base + sp->vdata->feature_reg);

    if ( (val == 0xffffffff) || (!(val & PSP_CAPABILITY_SEV)) )
        return -ENODEV;

    sp->capability = val;

    return 0;
}

static int __init sp_get_state(struct amd_sp_dev *sp, int *state, int *err)
{
    struct sev_user_data_status status;
    int rc;

    rc = _sev_do_cmd_sync(sp, SEV_CMD_PLATFORM_STATUS, &status, err);
    if ( rc )
        return rc;

    *state     = status.state;

    return 0;
}

static int __init sp_get_api_version(struct amd_sp_dev *sp)
{
    struct sev_user_data_status status;
    int err, rc;

    rc = _sev_do_cmd_sync(sp, SEV_CMD_PLATFORM_STATUS, &status, &err);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't get API version (%d 0x%x)\n",
                &sp->pdev->sbdf, rc, err);
        return rc;
    }

    sp->api_major = status.api_major;
    sp->api_minor = status.api_minor;
    sp->state     = status.state;

    return 0;
}

static int __init sp_update_firmware(struct amd_sp_dev *sp)
{
        /*
         * FIXME: nothing to do for now
         */
    return 0;
}

static int __init sp_alloc_special_regions(struct amd_sp_dev *sp)
{
        /*
         * FIXME: allocate TMP memory area for SEV-ES
         */
    return 0;
}

static int __init sp_do_init(struct amd_sp_dev *sp)
{
    struct sev_data_init data;
    int err, rc;

    if ( sp->state == SEV_STATE_INIT )
        return 0;

    memset(&data, 0, sizeof(data));

    rc = _sev_do_cmd_sync(sp, SEV_CMD_INIT, &data, &err);
    if ( rc )
        dprintk(XENLOG_ERR, "asp-%pp: can't init device: (%d 0x%x)\n", &sp->pdev->sbdf, rc, err);

    return 0;
}

static int __init sp_df_flush(struct amd_sp_dev *sp)
{
    int rc, err;

    rc = _sev_do_cmd_sync(sp, SEV_CMD_DF_FLUSH, NULL, &err);
    if ( rc )
        dprintk(XENLOG_ERR, "asp-%pp: can't flush device: (%d 0x%x)\n", &sp->pdev->sbdf, rc, err);

    return 0;
}

static int __init sp_dev_init(struct amd_sp_dev *sp)
{
    int err, rc;

    rc = sp_get_capability(sp);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "asp-%pp: capability is broken %d\n",
		&sp->pdev->sbdf, rc);
        return rc;
    }

    rc = sp_get_api_version(sp);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't get API version %d\n",
		&sp->pdev->sbdf, rc);
        return rc;
    }

    rc = sp_update_firmware(sp);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't update firmware %d\n",
		&sp->pdev->sbdf, rc);
        return rc;
    }

    rc = sp_alloc_special_regions(sp);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't alloc special regions %d\n",
		&sp->pdev->sbdf, rc);
        return rc;
    }

    rc = sp_do_init(sp);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't init device %d\n", &sp->pdev->sbdf,
		rc);
        return rc;
    }

    on_each_cpu(invalidate_cache, NULL, 1);

    rc = sp_df_flush(sp);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't flush %d\n", &sp->pdev->sbdf, rc);
        return rc;
    }

    rc = sp_get_state(sp, &sp->state, &err);
    if ( rc )
        dprintk(XENLOG_ERR, "asp-%pp: can't get sate %d\n", &sp->pdev->sbdf,rc);


    if ( sp->state != SEV_STATE_INIT )
    {
        dprintk(XENLOG_ERR, "asp-%pp: device is not inited 0x%x\n",
		&sp->pdev->sbdf, sp->state);
        return rc;
    }

    printk(XENLOG_INFO "inited asp-%pp device\n", &sp->pdev->sbdf);
    return 0;
}

static int __init sp_init_irq(struct amd_sp_dev *sp)
{
    int irq, rc;
    struct msi_info minfo;
    struct msi_desc *mdesc;

    /* Disable and clear interrupts until ready */
    writel(0, sp->io_base + sp->vdata->inten_reg);
    writel(-1, sp->io_base + sp->vdata->intsts_reg);

    irq = create_irq(0, false);
    if ( !irq )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't create interrupt\n", &sp->pdev->sbdf);
        return -EBUSY;
    }

    minfo.sbdf = sp->pdev->sbdf;
    minfo.irq  = irq;
    minfo.entry_nr = 1;
    if ( pci_find_cap_offset(sp->pdev->sbdf, PCI_CAP_ID_MSI) )
        minfo.table_base = 0;
    else {
        dprintk(XENLOG_ERR, "asp-%pp: only MSI is handled\n", &sp->pdev->sbdf);
        return -EINVAL;
    }

    mdesc = NULL;

    pcidevs_lock();

    rc = pci_enable_msi(sp->pdev, &minfo, &mdesc);
    if ( !rc )
    {
        struct irq_desc *idesc = irq_to_desc(irq);
        unsigned long flags;

        spin_lock_irqsave(&idesc->lock, flags);
        rc = setup_msi_irq(idesc, mdesc);
        spin_unlock_irqrestore(&idesc->lock, flags);
        if ( rc ) {
            pci_disable_msi(mdesc);
	    dprintk(XENLOG_ERR, "asp-%pp: can't setup msi %d\n", &sp->pdev->sbdf, rc);
	}
    }

    pcidevs_unlock();

    if ( rc)
    {
        if ( mdesc )
            msi_free_irq(mdesc);
	else
            destroy_irq(irq);
        return rc;

    }

    rc = request_irq(irq, 0, sp_interrupt_handler, "amd_sp", sp);

    if ( rc )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't request interrupt %d\n", &sp->pdev->sbdf, rc);
        return rc;
    }

    sp->irq = irq;

        /* Enable interrupts */
    writel(-1, sp->io_base + sp->vdata->inten_reg);

    return 0;
}

static int __init sp_map_iomem(struct amd_sp_dev *sp)
{
    uint32_t base_low;
    uint32_t base_high;
    uint16_t cmd;
    size_t   size;
    bool     high_space;

    base_low = pci_conf_read32(sp->pdev->sbdf, sp->vdata->base_offset);

    if ( (base_low & PCI_BASE_ADDRESS_SPACE) != PCI_BASE_ADDRESS_SPACE_MEMORY )
        return -EINVAL;

    if ( (base_low & PCI_BASE_ADDRESS_MEM_TYPE_MASK) == PCI_BASE_ADDRESS_MEM_TYPE_64 )
    {
        base_high = pci_conf_read32(sp->pdev->sbdf, sp->vdata->base_offset + 4);
        high_space = true;
    } else {
        base_high = 0;
        high_space = false;
    }

    sp->io_pbase = ((paddr_t)base_high << 32) | (base_low & PCI_BASE_ADDRESS_MEM_MASK);
    ASSERT(sp->io_pbase);

    pci_conf_write32(sp->pdev->sbdf, sp->vdata->base_offset, 0xFFFFFFFF);

    if ( high_space ) {
        pci_conf_write32(sp->pdev->sbdf, sp->vdata->base_offset + 4, 0xFFFFFFFF);
        size = (size_t)pci_conf_read32(sp->pdev->sbdf, sp->vdata->base_offset + 4) << 32;
    } else
        size = ~0xffffffffUL;

    size |= pci_conf_read32(sp->pdev->sbdf, sp->vdata->base_offset);
    sp->io_size = ~(size & PCI_BASE_ADDRESS_MEM_MASK) + 1;

    pci_conf_write32(sp->pdev->sbdf, sp->vdata->base_offset, base_low);

    if ( high_space )
          pci_conf_write32(sp->pdev->sbdf, sp->vdata->base_offset + 4, base_high);

    cmd = pci_conf_read16(sp->pdev->sbdf, PCI_COMMAND);
    pci_conf_write16(sp->pdev->sbdf, PCI_COMMAND, cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);

    sp->io_base = ioremap(sp->io_pbase, sp->io_size);
    if ( !sp->io_base )
        return -EFAULT;

    if ( pci_ro_device(0, sp->pdev->bus, sp->pdev->devfn) )
    {
	dprintk(XENLOG_ERR, "asp-%pp: can't hide PCI device\n",&sp->pdev->sbdf);
	return -EFAULT;
    }

    return 0;
}

static int  __init sp_dev_create(struct pci_dev *pdev, struct psp_vdata *vdata)
{
    struct amd_sp_dev *sp;
    int rc;

    sp = xzalloc(struct amd_sp_dev);
    if ( !sp )
        return -ENOMEM;

    sp->pdev = pdev;
    sp->vdata = vdata;
    sp->state = SEV_STATE_UNINIT;

    init_timer(&sp->cmd_timer, do_sp_cmd_timer, (void*)sp, 0);

    init_waitqueue_head(&sp->cmd_in_progress);

    rc = sp_map_iomem(sp);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't map iomem %d\n", &sp->pdev->sbdf, rc);
        return rc;
    }

    rc = sp_init_irq(sp);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't init irq %d\n", &sp->pdev->sbdf, rc);
        return rc;
    }

    sp->cmd_buff = alloc_xenheap_pages(get_order_from_bytes(ASP_CMD_BUFF_SIZE), 0);
    if ( !sp->cmd_buff )
    {
        dprintk(XENLOG_ERR, "asp-%pp: can't allocate cmd buffer\n", &sp->pdev->sbdf);
        return -ENOMEM;
    }

    sp->cbuff_pa_low = (uint32_t)(__pa(sp->cmd_buff));
    sp->cbuff_pa_high = (uint32_t)(__pa(sp->cmd_buff) >> 32);

    list_add(&sp->list, &amd_sp_units);

    amd_sp_master = sp;

    printk(XENLOG_INFO "discovered asp-%pp device\n", &sp->pdev->sbdf);

    return 0;
}

static void sp_dev_destroy(struct amd_sp_dev* sp)
{
    if( sp->io_base )
	writel(0, sp->io_base + sp->vdata->inten_reg);

    if ( sp->cmd_buff )
	free_xenheap_pages(sp->cmd_buff, get_order_from_bytes(ASP_CMD_BUFF_SIZE));

    xfree(sp);
}

static void sp_devs_destroy(void)
{
    struct amd_sp_dev *sp, *next;

    list_for_each_entry_safe ( sp, next, &amd_sp_units, list)
    {
        list_del(&sp->list);
        sp_dev_destroy(sp);
    }
}

static int __init amd_sp_probe(void)
{
    int bus = 0, devfn = 0, rc;
    struct  amd_sp_dev *sp;

     if ( !boot_cpu_has(X86_FEATURE_SEV) )
     {
	 dprintk(XENLOG_INFO, "AMD SEV isn't supported on the platform\n");
	 return 0;
     }

     if ( boot_cpu_has(X86_FEATURE_XEN_SHSTK) )
     {
	 force_sync = true;

	 dprintk(XENLOG_INFO,"AMD SEV: CET-SS detected - sync mode forced\n");
     }

    for ( bus = 0; bus < 256; ++bus )
        for ( devfn = 0; devfn < 256; ++devfn )
        {
            struct pci_dev *pdev;
            pcidevs_lock();
            pdev = pci_get_pdev(NULL, PCI_SBDF(0, bus, devfn));
            pcidevs_unlock();

            if ( !pdev || pci_conf_read16(pdev->sbdf, PCI_VENDOR_ID) !=
                 PCI_VENDOR_ID_AMD )
                continue;

            switch ( pci_conf_read16(pdev->sbdf, PCI_DEVICE_ID) )
            {
            case 0x1456:
                rc = sp_dev_create(pdev, &pspv1);
                break;
            case 0x1486:
                rc = sp_dev_create(pdev, &pspv2);
                break;
            case 0x14CA:
                rc = sp_dev_create(pdev, &pspv4);
                break;
            case 0x156E:
                rc = sp_dev_create(pdev, &pspv6);
                break;
            default:
                rc = 0;
                break;
            }
            if ( rc ) {
                goto err;
            }
        }

    for_each_sp_unit(sp)
    {
        rc = sp_dev_init(sp);
        if ( rc )
            goto err;
    }

    return 0;

  err:
    sp_devs_destroy();
    return rc;
}

__initcall(amd_sp_probe);
