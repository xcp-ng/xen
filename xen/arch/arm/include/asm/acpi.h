/*
 *  Copyright (C) 2015, Shannon Zhao <shannon.zhao@linaro.org>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#ifndef _ASM_ARM_ACPI_H
#define _ASM_ARM_ACPI_H

#include <asm/setup.h>

#define COMPILER_DEPENDENT_INT64   long long
#define COMPILER_DEPENDENT_UINT64  unsigned long long
#define ACPI_MAP_MEM_ATTR          PAGE_HYPERVISOR

/* Tables marked as reserved in efi table */
typedef enum {
    TBL_FADT,
    TBL_MADT,
    TBL_STAO,
    TBL_XSDT,
    TBL_RSDP,
    TBL_EFIT,
    TBL_MMAP,
    TBL_MMAX,
} EFI_MEM_RES;

bool acpi_psci_present(void);
bool acpi_psci_hvc_present(void);
void acpi_smp_init_cpus(void);

/*
 * This function returns the offset of a given ACPI/EFI table in the allocated
 * memory region. Currently, the tables should be created in the same order as
 * their associated 'index' in the enum EFI_MEM_RES. This means the function
 * won't return the correct offset until all the tables before a given 'index'
 * are created.
 */
paddr_t acpi_get_table_offset(struct membank tbl_add[], EFI_MEM_RES index);

/*
 * MADT GICC minimum length refers to the MADT GICC structure table length as
 * defined in the earliest ACPI version supported on arm64, ie ACPI 5.1.
 *
 * The efficiency_class member was added to the
 * struct acpi_madt_generic_interrupt to represent the MADT GICC structure
 * "Processor Power Efficiency Class" field, added in ACPI 6.0 whose offset
 * is therefore used to delimit the MADT GICC structure minimum length
 * appropriately.
 */
#define ACPI_MADT_GICC_MIN_LENGTH   ACPI_OFFSET( \
    struct acpi_madt_generic_interrupt, efficiency_class)

#define BAD_MADT_GICC_ENTRY(entry, end) \
    (!(entry) || (entry)->header.length < ACPI_MADT_GICC_MIN_LENGTH || \
    (unsigned long)(entry) + (entry)->header.length > (end))

#ifdef CONFIG_ACPI
extern bool acpi_disabled;
/* Basic configuration for ACPI */
static inline void disable_acpi(void)
{
    acpi_disabled = true;
}

static inline void enable_acpi(void)
{
    acpi_disabled = false;
}
#else
#define disable_acpi()
#define enable_acpi()
#endif

#endif /*_ASM_ARM_ACPI_H*/
