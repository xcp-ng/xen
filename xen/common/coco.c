/******************************************************************************
 * coco.c
 */

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/domain.h>

long
do_dom_coco_op(unsigned int cmd, domid_t domid, uint64_t arg1, uint64_t arg2)
{
#ifdef CONFIG_X86
    return arch_dom_coco_op(cmd, domid, arg1, arg2);
#else
    return -ENOSYS;
#endif
}
