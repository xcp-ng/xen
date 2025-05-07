#ifndef _XEN_COCO_H
#define _XEN_COCO_H

#include <asm/nospec.h>

#include <xen/stdint.h>
#include <xen/sched.h>

#include <public/domctl.h>
#include <public/hvm/coco.h>

extern __read_mostly struct coco_platform_status platform_status;

struct coco_domain_ops {
    int (*prepare_initial_mem)(struct domain *d, gfn_t gfn, size_t page_count);

    /* HVM domain hooks */
    int (*domain_initialise)(struct domain *d);
    int (*domain_creation_finished)(struct domain *d);
    int (*domain_teardown)(struct domain *d);
    void (*domain_destroy)(struct domain *d);

    /* Returns false if the general handler needs to be used. */
    bool (*show_execution_state)(struct vcpu *v);

#ifdef CONFIG_X86
    /* COCO-specific ASID allocation logic */
    int (*asid_alloc)(struct domain *d, struct hvm_asid *asid);
#endif
};

struct coco_ops {
    const char *name;
    
    int (*init)(void);
    int (*get_platform_status)(coco_platform_status_t *status);
    struct coco_domain_ops *(*get_domain_ops)(struct domain *d,
        const struct xen_domctl_createdomain *config);
};

void __init coco_register_ops(struct coco_ops *ops);
int __init coco_init(void);
void coco_set_domain_ops(struct domain *d, const struct xen_domctl_createdomain *config);

#ifdef CONFIG_COCO
static inline bool coco_is_supported(void)
{
    return evaluate_nospec(platform_status.flags & COCO_STATUS_FLAG_supported);
}

static inline int coco_domain_initialise(struct domain *d)
{
    if ( d->coco_ops && d->coco_ops->domain_initialise )
        return d->coco_ops->domain_initialise(d);

    return 0;
}

static inline int coco_domain_creation_finished(struct domain *d)
{
    if ( d->coco_ops && d->coco_ops->domain_creation_finished )
        return d->coco_ops->domain_creation_finished(d);

    return 0;
}

static inline int coco_domain_teardown(struct domain *d)
{
    if ( d->coco_ops && d->coco_ops->domain_teardown )
        return d->coco_ops->domain_teardown(d);

    return 0;
}

static inline void coco_domain_destroy(struct domain *d)
{
    if ( d->coco_ops && d->coco_ops->domain_destroy )
        d->coco_ops->domain_destroy(d);
}

static inline bool coco_show_execution_state(struct vcpu *v)
{
    struct domain *d = v->domain;

    if ( d->coco_ops && d->coco_ops->show_execution_state )
        return d->coco_ops->show_execution_state(v);

    return false;
}
#else
static inline bool coco_is_supported(void)
{
    return false;
}

static inline int coco_domain_initialise(struct domain *d)
{
    return 0;
}

static inline int coco_domain_creation_finished(struct domain *d)
{
    return 0;
}

static inline void coco_domain_destroy(struct domain *d)
{
}

static inline int coco_domain_teardown(struct domain *d)
{
    return 0;
}

static inline bool coco_show_execution_state(struct vcpu *v)
{
    return false;
}
#endif

#endif /* _XEN_COCO_H */