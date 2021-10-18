/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * ssdt_tpm2.asl
 *
 * Copyright (c) 2018-2022, Citrix Systems, Inc.
 */

/* SSDT for TPM CRB Interface for Xen with Qemu device model. */

DefinitionBlock ("SSDT_TPM2.aml", "SSDT", 2, "Xen", "HVM", 0)
{
    Device (TPM)
    {
        Name (_HID, "MSFT0101" /* TPM 2.0 Security Device */)  // _HID: Hardware ID
        Name (_CRS, ResourceTemplate ()  // _CRS: Current Resource Settings
        {
            Memory32Fixed (ReadWrite,
                0xFED40000,         // Address Base
                0x00001000,         // Address Length
                )
        })

        // IO port address must match the one in varstored
        OperationRegion (TPP2, SystemIO, 0x0104, 0x8)

        // byte access to TPP2 values
        // (index access is always 32-bit)
        Field (TPP2, DwordAcc, NoLock, Preserve)
        {
            IDXB, 32,
            AccessAs(ByteAcc),
            VALB, 8,
        }

        // double word (32 bit) access to TPP2 values
        Field (TPP2, DwordAcc, NoLock, Preserve)
        {
            IDXD, 32,
            VALD, 32,
        }

        // Read a byte from the PPI region
        // Arg0 is the offset into the region
        Method (TPRB, 1, Serialized)
        {
            IDXB = Arg0
            Return (VALB)
        }

        // Write a double word (32 bits) to the PPI region
        // Arg0 is the offset into the region
        // Arg1 is the double word to be written.
        Method (TPWD, 2, Serialized)
        {
            IDXD = Arg0
            VALD = Arg1
        }

        // Read a double word (32 bits) from the PPI region
        // Arg0 is the offset into the region
        Method (TPRD, 1, Serialized)
        {
            IDXD = Arg0
            Return (VALD)
        }

        // PPI region offsets from
        // https://qemu.readthedocs.io/en/latest/specs/tpm.html#acpi-ppi-interface
        Name (PPRP, 0x105)
        Name (PPRQ, 0x109)
        Name (PPRM, 0x10D)
        Name (LPPR, 0x111)

        Method (TPFN, 1, Serialized)
        {
            // returns operation flags
            If (Arg0 >= 0x100) {
                Return (0)
            }
            Return (TPRB (Arg0))
        }

        Method (_STA, 0, NotSerialized)  // _STA: Status
        {
            Return (0x0F)
        }

        // Use global TPM2 & TPM3 variables to workaround Windows ACPI bug
        // when returning packages.
        Name (TPM2, Package (0x2) { 0, 0 })
        Name (TPM3, Package (0x3) { 0, 0, 0 })

        Method (_DSM, 4, Serialized)
        {
            // Arg0: UUID
            // Arg1: revision
            // Arg2: function

            // Local0: operation op
            // Local1: operation flags

            /* Physical Presence Interface */
            If ((Arg0 == ToUUID ("3DDDFAA6-361B-4eb4-A424-8D10089D1653"))) {

                // _DSM query function
                If (Arg2 == 0) {
                    Return (Buffer (2) { 0xff, 0x1 }) /* function 1-8 */
                }

                // Get Physical Presence Interface Version
                If (Arg2 == 1) {
                    Return ("1.3")
                }

                // Submit TPM Operation Request to Pre-OS Environment
                If (Arg2 == 2) {
                    Local0 = DerefOf (Arg3 [0]) // opcode
                    Local1 = TPFN (Local0) // op flags

                    // FUNC_NOT_IMPLEMENTED or FUNC_BIOS_ONLY or FUNC_BLOCKED
                    if ((Local1 >= 0) && (Local1 <= 2)) {
                        Return (1)
                    }

                    // operation is FUNC_ALLOWED_USR_{,NOT_}REQ

                    TPWD (PPRQ, Local0)
                    TPWD (PPRM, 0)
                    Return (0)
                }

                // Get Pending TPM Operation Requested By the OS
                If (Arg2 == 3) {
                    If (Arg1 == 1) {
                        TPM2[1] = TPRD (PPRQ)
                        Return (TPM2)
                    }
                    If (Arg1 == 2) {
                        TPM3[1] = TPRD (PPRQ)
                        TPM3[2] = TPRD (PPRM)
                        Return (TPM3)
                    }
                }

                // Get Platform-Specific Action to Transition to Pre-OS Environment
                If (Arg2 == 4) {
                    Return (2) // Reboot
                }

                // Return TPM Operation Response to OS Environment
                If (Arg2 == 5) {
                    TPM3[1] = TPRD (LPPR)
                    TPM3[2] = TPRD (PPRP)
                    Return (TPM3)
                }

                // Submit preferred user language
                If (Arg2 == 6) {
                    Return (0x3) // not implemented
                }

                // Submit TPM Operation Request to Pre-OS Environment 2
                If (Arg2 == 7) {
                    Local0 = DerefOf (Arg3 [0]) // opcode
                    Local1 = TPFN (Local0) // op flags

                    // FUNC_NOT_IMPLEMENTED or FUNC_BIOS_ONLY
                    if ((Local1 == 0) || (Local1 == 1)) {
                        Return (1)
                    }

                    // FUNC_BLOCKED
                    if (Local1 == 2) {
                        Return (3)
                    }

                    // operation is FUNC_ALLOWED_USR_{,NOT_}REQ

                    // Rev ID == 1
                    If (Arg1 == 1) {
                        TPWD (PPRQ, Local0)
                        TPWD (PPRM, 0)
                    }

                    // Rev ID == 2
                    If (Arg1 == 2) {
                        TPWD (PPRQ, Local0)
                        TPWD (PPRM, DerefOf (Arg3[1]))
                    }

                    Return (0)
                }

                // Get User Confirmation Status for Operation
                If (Arg2 == 8) {
                    Local0 = DerefOf (Arg3 [0]) // opcode
                    Return (TPFN (Local0)) // op flags
                }

            }
            Return (Buffer (1) { 0x00 })
        }
    }
}
