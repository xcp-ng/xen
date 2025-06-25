#include <xen/lib.h>

void rust_stub_printk(char *buffer)
{
    printk("%s", buffer);
}