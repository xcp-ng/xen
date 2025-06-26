/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __XEN_RUST_H__
#define __XEN_RUST_H__

#include <xen/types.h>

int rust_demangle_symbol(const char *symbol, size_t symbol_size, char *output,
                         size_t output_size);

int rust_cbor_process(const uint8_t *input, size_t input_size, uint8_t *output,
                      size_t output_size, size_t *output_len);

#endif /* __XEN_RUST_H__ */