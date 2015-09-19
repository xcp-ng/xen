/* Coverity Scan model
 *
 * This is a modelling file for Coverity Scan. Modelling helps to avoid false
 * positives.
 *
 * - A model file can't import any header files.
 * - Therefore only some built-in primitives like int, char and void are
 *   available but not NULL etc.
 * - Modelling doesn't need full structs and typedefs. Rudimentary structs
 *   and similar types are sufficient.
 * - An uninitialised local pointer is not an error. It signifies that the
 *   variable could be either NULL or have some data.
 *
 * Coverity Scan doesn't pick up modifications automatically. The model file
 * must be uploaded by an admin in the analysis.
 *
 * The Xen Coverity Scan modelling file used the cpython modelling file as a
 * reference to get started (suggested by Coverty Scan themselves as a good
 * example), but all content is Xen specific.
 *
 * Copyright (c) 2013-2014 Citrix Systems Ltd; All Right Reserved
 *
 * Based on:
 *     http://hg.python.org/cpython/file/tip/Misc/coverity_model.c
 * Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
 * 2011, 2012, 2013 Python Software Foundation; All Rights Reserved
 *
 */

/*
 * Useful references:
 *   https://scan.coverity.com/models
 */

/* Definitions */
#define NULL (void *)0
#define PAGE_SIZE 4096UL
#define PAGE_MASK (~(PAGE_SIZE-1))

#define assert(cond) /* empty */

typedef unsigned int uint32_t;
typedef unsigned long xen_pfn_t;

struct page_info {};
struct pthread_mutex_t {};

struct xc_interface_core {};
typedef struct xc_interface_core xc_interface;

struct libxl__ctx
{
    struct pthread_mutex_t lock;
};
typedef struct libxl__ctx libxl_ctx;

/*
 * Xen malloc.  Behaves exactly like regular malloc(), except it also contains
 * an alignment parameter.
 *
 * TODO: work out how to correctly model bad alignments as errors.
 */
void *_xmalloc(unsigned long size, unsigned long align)
{
    int has_memory;

    __coverity_negative_sink__(size);
    __coverity_negative_sink__(align);

    if ( has_memory )
        return __coverity_alloc__(size);
    else
        return NULL;
}

/*
 * Xen free.  Frees a pointer allocated by _xmalloc().
 */
void xfree(void *va)
{
    __coverity_free__(va);
}


/*
 * map_domain_page() takes an existing domain page and possibly maps it into
 * the Xen pagetables, to allow for direct access.  Model this as a memory
 * allocation of exactly 1 page.
 *
 * map_domain_page() never fails. (It will BUG() before returning NULL)
 */
void *map_domain_page(unsigned long mfn)
{
    unsigned long ptr = (unsigned long)__coverity_alloc__(PAGE_SIZE);

    /*
     * Expressing the alignment of the memory allocation isn't possible.  As a
     * substitute, tell Coverity to ignore any path where ptr isn't page
     * aligned.
     */
    if ( ptr & ~PAGE_MASK )
        __coverity_panic__();

    return (void *)ptr;
}

/*
 * unmap_domain_page() will unmap a page.  Model it as a free().  Any *va
 * within the page is valid to pass.
 */
void unmap_domain_page(const void *va)
{
    unsigned long ptr = (unsigned long)va & PAGE_MASK;

    __coverity_free__((void *)ptr);
}

/*
 * Coverity appears not to understand that errx() unconditionally exits.
 */
void errx(int, const char*, ...)
{
    __coverity_panic__();
}

/*
 * Coverity doesn't appear to be certain that the libxl ctx->lock is recursive.
 */
void libxl__ctx_lock(libxl_ctx *ctx)
{
    __coverity_recursive_lock_acquire__(&ctx->lock);
}

void libxl__ctx_unlock(libxl_ctx *ctx)
{
    __coverity_recursive_lock_release__(&ctx->lock);
}

/*
 * Coverity doesn't understand our unreachable() macro, which causes it to
 * incorrectly find issues based on continuing execution along unreachable
 * paths.
 */
void unreachable(void)
{
    __coverity_panic__();
}


typedef void* va_list;

int asprintf(char **strp, const char *fmt, ...)
{
    char ch1;
    int success;
    unsigned int total_bytes_printed;

    /* fmt must be NUL terminated, and reasonably bounded */
    __coverity_string_null_sink__((void*)fmt);
    __coverity_string_size_sink__((void*)fmt);

    /* Reads fmt */
    ch1 = *fmt;

    if ( success )
    {
        /* Allocates a string.  Exact size is not calculable */
        char *str = __coverity_alloc_nosize__();

        /* Should be freed with free() */
        __coverity_mark_as_afm_allocated__(str, AFM_free);

        /* Returns memory via first parameter */
        *strp = str;

        /* Writes to all of the allocated string */
        __coverity_writeall__(str);

        /* Returns a positive number of bytes printed on success */
        return total_bytes_printed;
    }
    else
    {
        /* Return -1 on failure */
        return -1;
    }
}

int vasprintf(char **strp, const char *fmt, va_list ap)
{
    char ch1;
    int success;
    unsigned int total_bytes_printed;

    /* fmt must be NUL terminated, and reasonably bounded */
    __coverity_string_null_sink__((void*)fmt);
    __coverity_string_size_sink__((void*)fmt);

    /* Reads fmt */
    ch1 = *fmt;

    /* Reads ap */
    ch1 = *(char*)ap;

    if ( success )
    {
        /* Allocates a string.  Exact size is not calculable */
        char *str = __coverity_alloc_nosize__();

        /* Should be freed with free() */
        __coverity_mark_as_afm_allocated__(str, AFM_free);

        /* Returns memory via first parameter */
        *strp = str;

        /* Writes to all of the allocated string */
        __coverity_writeall__(str);

        /* Returns a positive number of bytes printed on success */
        return total_bytes_printed;
    }
    else
    {
        /* Return -1 on failure */
        return -1;
    }
}

void cpuid_count(unsigned leaf, unsigned subleaf,
                 unsigned *eax, unsigned *ebx,
                 unsigned *ecx, unsigned *edx)
{
    unsigned f;

    *eax = f;
    *ebx = f;
    *ecx = f;
    *edx = f;
}

int __builtin_constant_p(unsigned long expr)
{
    int x;

    if ( x )
        return 1;
    else
        return 0;
}

int read(int fd, void *buf, size_t count);
int read_exact(int fd, void *data, size_t size)
{
    return read(fd, data, size);
}

void *xc_map_foreign_bulk(xc_interface *xch, uint32_t dom, int prot,
                          const xen_pfn_t *arr, int *err, unsigned int num)
{
    xc_interface interface;
    xen_pfn_t pfn;
    int success, errval;
    unsigned int i;

    /* 1) Reads 'xch'. */
    interface = *xch;

    /* 2) Sink negative array lengths. */
    __coverity_negative_sink__(num);

    /* 3) Reads every element in arr. */
    for ( i = 0; i < num; ++i )
        pfn = arr[i];

    if ( success )
    {
        /*
         * 4) In the success case, return an allocated area of 'num' pages
         * which must be munmap()'d, and write to every element in 'err'.
         */
        void *area = __coverity_alloc__(num * PAGE_SIZE);

        for ( i = 0; i < num; ++i )
            err[i] = errval;

        return area;
    }
    else
        return NULL;
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
