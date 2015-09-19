#ifndef XEN__LOCKDOWN_H
#define XEN__LOCKDOWN_H

#include <xen/types.h>

bool is_locked_down(void);
void lockdown_init(const char *cmdline);

#endif /* XEN__LOCKDOWN_H */
