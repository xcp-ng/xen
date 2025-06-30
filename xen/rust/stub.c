#include <xen/sched.h>
#include <xen/lib.h>

void rust_stub_printk(char *buffer)
{
    printk("%s", buffer);
}

void rust_stub_put_domain(struct domain *d)
{
    put_domain(d);
}