#include <xen/init.h>
#include <asm/msr.h>

/*
 * Valid values:
 *   1 => Explicit tsx=1
 *   0 => Explicit tsx=0
 *  -1 => Default, implicit tsx=1, may change to 0 to mitigate TAA
 *  -3 => Implicit tsx=1 (feed-through from spec-ctrl=0)
 *
 * This is arranged such that the bottom bit encodes whether TSX is actually
 * disabled, while identifying various explicit (>=0) and implicit (<0)
 * conditions.
 */
int8_t __read_mostly opt_tsx = -1;
int8_t __read_mostly cpu_has_tsx_ctrl = -1;

static int __init parse_tsx(const char *s)
{
    int rc = 0, val = parse_bool(s, NULL);

    if ( val >= 0 )
        opt_tsx = val;
    else
        rc = -EINVAL;

    return rc;
}
custom_param("tsx", parse_tsx);

void tsx_init(void)
{
    /*
     * This function is first called between microcode being loaded, and CPUID
     * being scanned generally.  Read into boot_cpu_data.x86_capability[] for
     * the cpu_has_* bits we care about using here.
     */
    if ( unlikely(cpu_has_tsx_ctrl < 0) )
    {
        uint64_t caps = 0;

        if ( boot_cpu_data.cpuid_level >= 7 )
            boot_cpu_data.x86_capability[cpufeat_word(X86_FEATURE_ARCH_CAPS)]
                = cpuid_count_edx(7, 0);

        if ( cpu_has_arch_caps )
            rdmsrl(MSR_ARCH_CAPABILITIES, caps);

        cpu_has_tsx_ctrl = !!(caps & ARCH_CAPS_TSX_CTRL);
    }

    if ( cpu_has_tsx_ctrl )
    {
        uint32_t hi, lo;

        rdmsr(MSR_TSX_CTRL, lo, hi);

        lo &= ~(TSX_CTRL_RTM_DISABLE | TSX_CTRL_CPUID_CLEAR);
        /* Check bottom bit only.  Higher bits are various sentinals. */
        if ( !(opt_tsx & 1) )
            lo |= TSX_CTRL_RTM_DISABLE | TSX_CTRL_CPUID_CLEAR;

        wrmsr(MSR_TSX_CTRL, lo, hi);
    }
    else if ( opt_tsx >= 0 )
        printk_once(XENLOG_WARNING
                    "MSR_TSX_CTRL not available - Ignoring tsx= setting\n");
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
