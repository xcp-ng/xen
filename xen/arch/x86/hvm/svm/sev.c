#include <xen/lib.h>
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <asm/sev.h>
#include <asm/psp-sev.h>
#include <asm/hvm/svm/vmcb.h>

uint64_t __read_mostly pte_c_bit_mask;
unsigned int __read_mostly min_sev_asid;
unsigned int __read_mostly max_sev_asid;

long svm_dom_coco_op(unsigned int cmd, domid_t domid, uint64_t arg1,
                     uint64_t arg2)
{
  struct domain *d;
  int psp_ret;
  long rc = 0;

  if (!is_control_domain(current->domain))
    return -EINVAL;

  d = get_domain_by_id(domid);
  if (!d)
    return -EINVAL;

  if (!is_sev_domain(d))
    return -EINVAL;

  /* AS: actually serialization is done on driver level for polling mode
   * As we can't go to sleep (wait for interrupt) with lock held in Xen we have
   * to think if the serialization can be done on dom0 level and it is
   * acceptable to trust dom0 on that (:doubt:)
   */

  switch (cmd) {
  case COCO_DOM_INIT: {
    struct sev_data_launch_start sd_ls;
    struct sev_data_activate sd_a;

    sd_ls.handle = 0;          /* generate new one */
    sd_ls.policy = 0;          /* NOKS policy */
    sd_ls.dh_cert_address = 0; /* do not DH stuff */

    rc = sev_do_cmd(SEV_CMD_LAUNCH_START, (void *)(&sd_ls), &psp_ret, true);
    if (rc) {
      printk("%s: failed to LAUNCH_START domain(%d): psp_ret %d\n",
             __FUNCTION__, domid, psp_ret);
      return rc;
    }

    sd_a.handle = sd_ls.handle;
    sd_a.asid = d->arch.hvm.n1asid.asid;

    rc = sev_do_cmd(SEV_CMD_ACTIVATE, (void *)(&sd_a), &psp_ret, true);
    if (rc) {
      printk("%s: failed to ACTIVATE domain(%d): psp_ret %d\n", __FUNCTION__,
             domid, psp_ret);
      return rc;
    }

    d->arch.hvm.svm.asp_handle = sd_ls.handle;
    d->arch.hvm.svm.asp_policy = 0;

    return 0;
  }
  case COCO_DOM_ADD_MEM: {
    struct sev_data_launch_update_data sd_lud;

    /*AS: add sanity checks here on mem/handle/state*/

    sd_lud.handle = d->arch.hvm.svm.asp_handle;
    sd_lud.address = arg1; /* can we trust dom0 for paddr? */
    sd_lud.len = arg2;

    rc = sev_do_cmd(SEV_CMD_LAUNCH_UPDATE_DATA, (void *)(&sd_lud), &psp_ret,
                    true);
    if (rc) {
      printk("%s: failed to LAUNCH_UPDATE_DATA to domain(%d): psp_ret %d\n",
             __FUNCTION__, domid, psp_ret);
      return rc;
    }

    return 0;
  }
  case COCO_DOM_RUN: {
    struct sev_data_launch_measure sd_lm;
    struct sev_data_launch_finish sd_lf;
    struct vcpu *v;

    sd_lm.handle = d->arch.hvm.svm.asp_handle;
    sd_lm.address = __pa(d->arch.hvm.svm.measure);
    sd_lm.len = 32;

    rc = sev_do_cmd(SEV_CMD_LAUNCH_MEASURE, (void *)(&sd_lm), &psp_ret, true);
    if (rc) {
      printk("%s: failed to LAUNCH_MEASURE domain(%d): psp_ret %d\n",
             __FUNCTION__, domid, psp_ret);
      return rc;
    }

    sd_lf.handle = d->arch.hvm.svm.asp_handle;

    rc = sev_do_cmd(SEV_CMD_LAUNCH_FINISH, (void *)(&sd_lf), &psp_ret, true);
    if (rc) {
      printk("%s: failed to LAUNCH_FINISH domain(%d): psp_ret %d\n",
             __FUNCTION__, domid, psp_ret);
      return rc;
    }

    for_each_vcpu(d, v) {
      struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
      vmcb_set_np_ctrl(vmcb, vmcb_get_np_ctrl(vmcb) | NPCTRL_SEV_ENABLE);
    }

    return 0;
  }

  case COCO_DOM_FINI: {
  }
  case SEV_CMD_DEACTIVATE: {
    struct sev_data_deactivate sd_da;
    struct sev_data_decommission sd_de;

    sd_da.handle = d->arch.hvm.svm.asp_handle;

    rc = sev_do_cmd(SEV_CMD_DEACTIVATE, (void *)(&sd_da), &psp_ret, true);
    if (rc) {
      printk("%s: failed to DEACTIVATE domain(%d): psp_ret %d\n", __FUNCTION__,
             domid, psp_ret);
      return rc;
    }

    sd_de.handle = d->arch.hvm.svm.asp_handle;

    rc = sev_do_cmd(SEV_CMD_DECOMMISSION, (void *)(&sd_de), &psp_ret, true);
    if (rc) {
      printk("%s: failed to DEACOMMISSION domain(%d): psp_ret %d\n",
             __FUNCTION__, domid, psp_ret);
      return rc;
    }

    d->arch.hvm.svm.asp_handle = 0;
    return 0;
  }
  default:
    rc = -EINVAL;
  }
  printk("%s: cmd %d\n", __FUNCTION__, cmd);
  return rc;
}
