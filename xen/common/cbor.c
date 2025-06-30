#include <xen/xvmalloc.h>
#include <xen/guest_access.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/rust.h>

#define MAX_BUFFER_LENGTH 4096

long do_cbor_call(unsigned int op,
                  unsigned long input_len,
                  XEN_GUEST_HANDLE_PARAM(uint8) input,
                  unsigned long output_len,
                  XEN_GUEST_HANDLE_PARAM(uint8) output)
{
    uint8_t *input_buffer, *output_buffer;
    size_t processed_output_len = 0;
    long ret = 0;

    if (input_len > MAX_BUFFER_LENGTH || output_len > MAX_BUFFER_LENGTH)
        /* We reject too large buffers */
        return -E2BIG;

    input_buffer = xvmalloc_array(uint8_t, MAX_BUFFER_LENGTH);

    if ( copy_from_guest(input_buffer, input, input_len) )
    {
        xfree(input_buffer);
        return -EFAULT;
    }

    output_buffer = xvmalloc_array(uint8_t, MAX_BUFFER_LENGTH);

    ret = rust_cbor_process(input_buffer, input_len, output_buffer,
                            output_len, &processed_output_len);

    xfree(input_buffer);

    if ( !ret )
    {
        if ( copy_to_guest(output, output_buffer, processed_output_len) )
            ret = -EFAULT;
    }

    xfree(output_buffer);

    return ret;
}