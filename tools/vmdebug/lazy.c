#include <stdlib.h>

#include "vmdebug.h"

static xc_interface *global_xch = NULL;

xc_interface * get_xch(void)
{
    if ( global_xch )
        return global_xch;

    global_xch = xc_interface_open(NULL, NULL, 0);

    if ( !global_xch )
        exit(1);

    return global_xch;
}

void lazy_cleanup(void)
{
    if ( global_xch )
    {
        xc_interface_close(global_xch);
        global_xch = NULL;
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
