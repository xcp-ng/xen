#ifndef __VMDEBUG_H__
#define __VMDEBUG_H__

#include <xenctrl.h>

#define ARRAY_SIZE(a) (sizeof (a) / sizeof *(a))

typedef struct cmdopts
{
    int domid; /* -1 implies no domid given. */
} cmdopts_t;

int main_help(int argc, char **argv, const cmdopts_t *opts);
int main_hvmparam(int argc, char **argv, const cmdopts_t *opts);

typedef struct cmdspec
{
    const char *name;

    int (*main)(int argc, char **argv, const cmdopts_t *opts);

    const char *desc;
    const char *detail;
} cmdspec_t;

extern const cmdspec_t cmdtable[];

/* Obtain 'xch', opened in a lazy manner. */
xc_interface * get_xch(void);

/* Cleans up all lazily opened resources. */
void lazy_cleanup(void);

#endif /* __VMDEBUG_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
