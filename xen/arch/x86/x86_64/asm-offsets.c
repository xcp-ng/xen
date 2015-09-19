/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */
#define COMPILE_OFFSETS

#ifdef CONFIG_PERF_COUNTERS
#include <xen/perfc.h>
#endif
#include <xen/sched.h>
#ifdef CONFIG_PV32
#include <compat/xen.h>
#endif
#include <asm/hardirq.h>
#include <xen/multiboot.h>
#include <xen/multiboot2.h>
#include <public/sysctl.h>
#include <xen/symbols.h>
#include <xen/livepatch.h>
#include <xen/livepatch_payload.h>

#define DEFINE(_sym, _val)                                                 \
    asm volatile ("\n.ascii\"==>#define " #_sym " %0 /* " #_val " */<==\"" \
                  : : "i" (_val) )
#define BLANK()                                                            \
    asm volatile ( "\n.ascii\"==><==\"" : : )
#define OFFSET(_sym, _str, _mem)                                           \
    DEFINE(_sym, offsetof(_str, _mem));

void __dummy__(void)
{
    OFFSET(DOMAIN_id, struct domain, domain_id);
    OFFSET(DOMAIN_shared_info, struct domain, shared_info);
    OFFSET(DOMAIN_next, struct domain, next_in_list);
    OFFSET(DOMAIN_max_vcpus, struct domain, max_vcpus);
    OFFSET(DOMAIN_vcpus, struct domain, vcpu);
    // TODO - fix this up properly in combination with the crashdump analyser
    OFFSET(DOMAIN_options, struct domain, options);
    OFFSET(DOMAIN_is_privileged, struct domain, is_privileged);
    OFFSET(DOMAIN_tot_pages, struct domain, tot_pages);
    OFFSET(DOMAIN_max_pages, struct domain, max_pages);
#ifdef CONFIG_MEM_SHARING
    OFFSET(DOMAIN_shr_pages, struct domain, shr_pages);
#endif
    OFFSET(DOMAIN_has_32bit_shinfo, struct domain, arch.has_32bit_shinfo);
    OFFSET(DOMAIN_pause_count, struct domain, pause_count);
    OFFSET(DOMAIN_handle, struct domain, handle);
    OFFSET(DOMAIN_paging_mode, struct domain, arch.paging.mode);
    DEFINE(DOMAIN_sizeof, sizeof(struct domain));
    BLANK();

    OFFSET(SHARED_max_pfn, struct shared_info, arch.max_pfn);
    OFFSET(SHARED_pfn_to_mfn_list_list, struct shared_info, arch.pfn_to_mfn_frame_list_list);
    BLANK();

    DEFINE(VIRT_XEN_START, XEN_VIRT_START);
    DEFINE(VIRT_XEN_END, XEN_VIRT_END);
    DEFINE(VIRT_DIRECTMAP_START, DIRECTMAP_VIRT_START);
    DEFINE(VIRT_DIRECTMAP_END, DIRECTMAP_VIRT_END);
    BLANK();

    DEFINE(XEN_DEBUG, IS_ENABLED(CONFIG_DEBUG));
    DEFINE(XEN_FRAME_POINTER, IS_ENABLED(CONFIG_FRAME_POINTER));
    DEFINE(XEN_STACK_SIZE, STACK_SIZE);
    DEFINE(XEN_PRIMARY_STACK_SIZE, PRIMARY_STACK_SIZE);
    BLANK();

    OFFSET(VCPU_vcpu_id, struct vcpu, vcpu_id);
    OFFSET(VCPU_user_regs, struct vcpu, arch.user_regs);
    OFFSET(VCPU_flags, struct vcpu, arch.flags);
    OFFSET(VCPU_guest_table_user, struct vcpu, arch.guest_table_user);
    OFFSET(VCPU_guest_table, struct vcpu, arch.guest_table);
    OFFSET(VCPU_pause_flags, struct vcpu, pause_flags);
    OFFSET(VCPU_pause_count, struct vcpu, pause_count);
    DEFINE(VCPU_sizeof, sizeof(struct vcpu));
    BLANK();

    OFFSET(CPUINFO_processor_id, struct cpu_info, processor_id);
    BLANK();

    OFFSET(LIST_HEAD_next, struct list_head, next);
    BLANK();

#ifdef CONFIG_LIVEPATCH
    OFFSET(LIVEPATCH_payload_list, struct payload, list);
    OFFSET(LIVEPATCH_payload_state, struct payload, state);
    OFFSET(LIVEPATCH_payload_rc, struct payload, rc);
    OFFSET(LIVEPATCH_payload_buildid, struct payload, id.p);
    OFFSET(LIVEPATCH_payload_buildid_len, struct payload, id.len);
    OFFSET(LIVEPATCH_payload_text_addr, struct payload, text_addr);
    OFFSET(LIVEPATCH_payload_text_size, struct payload, text_size);
    OFFSET(LIVEPATCH_payload_rw_addr, struct payload, rw_addr);
    OFFSET(LIVEPATCH_payload_rw_size, struct payload, rw_size);
    OFFSET(LIVEPATCH_payload_ro_addr, struct payload, ro_addr);
    OFFSET(LIVEPATCH_payload_ro_size, struct payload, ro_size);
    OFFSET(LIVEPATCH_payload_applied_list, struct payload, applied_list);
    OFFSET(LIVEPATCH_payload_symtab, struct payload, symtab);
    OFFSET(LIVEPATCH_payload_nsyms, struct payload, nsyms);
    OFFSET(LIVEPATCH_payload_name, struct payload, name);
    DEFINE(LIVEPATCH_payload_name_max_len, XEN_LIVEPATCH_NAME_SIZE);
    OFFSET(LIVEPATCH_symbol_name, struct livepatch_symbol, name);
    OFFSET(LIVEPATCH_symbol_value, struct livepatch_symbol, value);
    DEFINE(LIVEPATCH_symbol_sizeof, sizeof(struct livepatch_symbol));
    DEFINE(LIVEPATCH_symbol_max_len, KSYM_NAME_LEN);
    BLANK();
#endif

    OFFSET(UREGS_r15, struct cpu_user_regs, r15);
    OFFSET(UREGS_r14, struct cpu_user_regs, r14);
    OFFSET(UREGS_r13, struct cpu_user_regs, r13);
    OFFSET(UREGS_r12, struct cpu_user_regs, r12);
    OFFSET(UREGS_rbp, struct cpu_user_regs, rbp);
    OFFSET(UREGS_rbx, struct cpu_user_regs, rbx);
    OFFSET(UREGS_r11, struct cpu_user_regs, r11);
    OFFSET(UREGS_r10, struct cpu_user_regs, r10);
    OFFSET(UREGS_r9, struct cpu_user_regs, r9);
    OFFSET(UREGS_r8, struct cpu_user_regs, r8);
    OFFSET(UREGS_rax, struct cpu_user_regs, rax);
    OFFSET(UREGS_rcx, struct cpu_user_regs, rcx);
    OFFSET(UREGS_rdx, struct cpu_user_regs, rdx);
    OFFSET(UREGS_rsi, struct cpu_user_regs, rsi);
    OFFSET(UREGS_rdi, struct cpu_user_regs, rdi);
    OFFSET(UREGS_error_code, struct cpu_user_regs, error_code);
    OFFSET(UREGS_entry_vector, struct cpu_user_regs, entry_vector);
    OFFSET(UREGS_rip, struct cpu_user_regs, rip);
    OFFSET(UREGS_cs, struct cpu_user_regs, cs);
    OFFSET(UREGS_eflags, struct cpu_user_regs, rflags);
    OFFSET(UREGS_rsp, struct cpu_user_regs, rsp);
    OFFSET(UREGS_ss, struct cpu_user_regs, ss);
    OFFSET(UREGS_kernel_sizeof, struct cpu_user_regs, es);
    BLANK();

    /*
     * EFRAME_* is for the entry/exit logic where %rsp is pointing at
     * UREGS_error_code and GPRs are still/already guest values.
     */
#define OFFSET_EF(sym, mem, ...)                                        \
    DEFINE(sym, offsetof(struct cpu_user_regs, mem) -                   \
                offsetof(struct cpu_user_regs, error_code) __VA_ARGS__)

    OFFSET_EF(EFRAME_entry_vector,    entry_vector);
    OFFSET_EF(EFRAME_rip,             rip);
    OFFSET_EF(EFRAME_cs,              cs);
    OFFSET_EF(EFRAME_eflags,          eflags);

    /*
     * These aren't real fields.  They're spare space, used by the IST
     * exit-to-xen path.
     */
    OFFSET_EF(EFRAME_shadow_scf,      eflags, +4);
    OFFSET_EF(EFRAME_shadow_sel,      eflags, +6);

    OFFSET_EF(EFRAME_rsp,             rsp);
    BLANK();

#undef OFFSET_EF

    OFFSET(VCPU_processor, struct vcpu, processor);
    OFFSET(VCPU_domain, struct vcpu, domain);
    OFFSET(VCPU_vcpu_info, struct vcpu, vcpu_info);
    OFFSET(VCPU_trap_bounce, struct vcpu, arch.pv.trap_bounce);
    OFFSET(VCPU_thread_flags, struct vcpu, arch.flags);
    OFFSET(VCPU_event_addr, struct vcpu, arch.pv.event_callback_eip);
    OFFSET(VCPU_event_sel, struct vcpu, arch.pv.event_callback_cs);
    OFFSET(VCPU_syscall_addr, struct vcpu, arch.pv.syscall_callback_eip);
    OFFSET(VCPU_syscall32_addr, struct vcpu, arch.pv.syscall32_callback_eip);
    OFFSET(VCPU_syscall32_sel, struct vcpu, arch.pv.syscall32_callback_cs);
    OFFSET(VCPU_syscall32_disables_events,
           struct vcpu, arch.pv.syscall32_disables_events);
    OFFSET(VCPU_sysenter_addr, struct vcpu, arch.pv.sysenter_callback_eip);
    OFFSET(VCPU_sysenter_sel, struct vcpu, arch.pv.sysenter_callback_cs);
    OFFSET(VCPU_sysenter_disables_events,
           struct vcpu, arch.pv.sysenter_disables_events);
    OFFSET(VCPU_trap_ctxt, struct vcpu, arch.pv.trap_ctxt);
    OFFSET(VCPU_kernel_sp, struct vcpu, arch.pv.kernel_sp);
    OFFSET(VCPU_kernel_ss, struct vcpu, arch.pv.kernel_ss);
    OFFSET(VCPU_iopl, struct vcpu, arch.pv.iopl);
    OFFSET(VCPU_guest_context_flags, struct vcpu, arch.pv.vgc_flags);
    OFFSET(VCPU_cr3, struct vcpu, arch.cr3);
    OFFSET(VCPU_arch_msrs, struct vcpu, arch.msrs);
    OFFSET(VCPU_nmi_pending, struct vcpu, arch.nmi_pending);
    OFFSET(VCPU_mce_pending, struct vcpu, arch.mce_pending);
    OFFSET(VCPU_nmi_old_mask, struct vcpu, arch.nmi_state.old_mask);
    OFFSET(VCPU_mce_old_mask, struct vcpu, arch.mce_state.old_mask);
    OFFSET(VCPU_async_exception_mask, struct vcpu, arch.async_exception_mask);
    DEFINE(VCPU_TRAP_NMI, VCPU_TRAP_NMI);
    DEFINE(VCPU_TRAP_MCE, VCPU_TRAP_MCE);
    DEFINE(_VGCF_syscall_disables_events,  _VGCF_syscall_disables_events);
    BLANK();

#ifdef CONFIG_HVM
    OFFSET(VCPU_svm_vmcb_pa, struct vcpu, arch.hvm.svm.vmcb_pa);
    OFFSET(VCPU_svm_vmcb, struct vcpu, arch.hvm.svm.vmcb);
    BLANK();

    OFFSET(VCPU_vmx_launched, struct vcpu, arch.hvm.vmx.launched);
    OFFSET(VCPU_vmx_realmode, struct vcpu, arch.hvm.vmx.vmx_realmode);
    OFFSET(VCPU_vmx_emulate, struct vcpu, arch.hvm.vmx.vmx_emulate);
    OFFSET(VCPU_vm86_seg_mask, struct vcpu, arch.hvm.vmx.vm86_segment_mask);
    OFFSET(VCPU_hvm_guest_cr2, struct vcpu, arch.hvm.guest_cr[2]);
    BLANK();

    OFFSET(VCPU_nhvm_guestmode, struct vcpu, arch.hvm.nvcpu.nv_guestmode);
    OFFSET(VCPU_nhvm_p2m, struct vcpu, arch.hvm.nvcpu.nv_p2m);
    OFFSET(VCPU_nsvm_hap_enabled, struct vcpu, arch.hvm.nvcpu.u.nsvm.ns_hap_enabled);
    BLANK();
#endif

#ifdef CONFIG_PV32
    OFFSET(DOMAIN_is_32bit_pv, struct domain, arch.pv.is_32bit);
    BLANK();

    OFFSET(COMPAT_VCPUINFO_upcall_pending, struct compat_vcpu_info, evtchn_upcall_pending);
    OFFSET(COMPAT_VCPUINFO_upcall_mask, struct compat_vcpu_info, evtchn_upcall_mask);
    BLANK();
#endif

#ifdef CONFIG_PV
    OFFSET(VCPUINFO_upcall_pending, struct vcpu_info, evtchn_upcall_pending);
    OFFSET(VCPUINFO_upcall_mask, struct vcpu_info, evtchn_upcall_mask);
    BLANK();
#endif

    OFFSET(CPUINFO_guest_cpu_user_regs, struct cpu_info, guest_cpu_user_regs);
    OFFSET(CPUINFO_error_code, struct cpu_info, guest_cpu_user_regs.error_code);
    OFFSET(CPUINFO_rip, struct cpu_info, guest_cpu_user_regs.rip);
    OFFSET(CPUINFO_verw_sel, struct cpu_info, verw_sel);
    OFFSET(CPUINFO_current_vcpu, struct cpu_info, current_vcpu);
    OFFSET(CPUINFO_per_cpu_offset, struct cpu_info, per_cpu_offset);
    OFFSET(CPUINFO_cr4, struct cpu_info, cr4);
    OFFSET(CPUINFO_xen_cr3, struct cpu_info, xen_cr3);
    OFFSET(CPUINFO_pv_cr3, struct cpu_info, pv_cr3);
    OFFSET(CPUINFO_shadow_spec_ctrl, struct cpu_info, shadow_spec_ctrl);
    OFFSET(CPUINFO_xen_spec_ctrl, struct cpu_info, xen_spec_ctrl);
    OFFSET(CPUINFO_last_spec_ctrl, struct cpu_info, last_spec_ctrl);
    OFFSET(CPUINFO_scf, struct cpu_info, scf);
    OFFSET(CPUINFO_root_pgt_changed, struct cpu_info, root_pgt_changed);
    OFFSET(CPUINFO_use_pv_cr3, struct cpu_info, use_pv_cr3);
    DEFINE(CPUINFO_sizeof, sizeof(struct cpu_info));
    BLANK();

#ifdef CONFIG_PV
    OFFSET(TRAPINFO_eip, struct trap_info, address);
    OFFSET(TRAPINFO_cs, struct trap_info, cs);
    OFFSET(TRAPINFO_flags, struct trap_info, flags);
    DEFINE(TRAPINFO_sizeof, sizeof(struct trap_info));
    BLANK();

    OFFSET(TRAPBOUNCE_error_code, struct trap_bounce, error_code);
    OFFSET(TRAPBOUNCE_flags, struct trap_bounce, flags);
    OFFSET(TRAPBOUNCE_cs, struct trap_bounce, cs);
    OFFSET(TRAPBOUNCE_eip, struct trap_bounce, eip);
    BLANK();
#endif

    OFFSET(VCPUMSR_spec_ctrl_raw, struct vcpu_msrs, spec_ctrl.raw);
    BLANK();

#ifdef CONFIG_PERF_COUNTERS
    DEFINE(ASM_PERFC_exceptions, PERFC_exceptions);
    BLANK();
#endif

    DEFINE(IRQSTAT_shift, ilog2(sizeof(irq_cpustat_t)));
    OFFSET(IRQSTAT_softirq_pending, irq_cpustat_t, __softirq_pending);
    BLANK();

    OFFSET(CPUINFO_features, struct cpuinfo_x86, x86_capability);
    BLANK();

    OFFSET(MB_flags, multiboot_info_t, flags);
    OFFSET(MB_cmdline, multiboot_info_t, cmdline);
    OFFSET(MB_mem_lower, multiboot_info_t, mem_lower);
    BLANK();

    DEFINE(MB2_fixed_sizeof, sizeof(multiboot2_fixed_t));
    OFFSET(MB2_fixed_total_size, multiboot2_fixed_t, total_size);
    OFFSET(MB2_tag_type, multiboot2_tag_t, type);
    OFFSET(MB2_tag_size, multiboot2_tag_t, size);
    OFFSET(MB2_load_base_addr, multiboot2_tag_load_base_addr_t, load_base_addr);
    OFFSET(MB2_mem_lower, multiboot2_tag_basic_meminfo_t, mem_lower);
    OFFSET(MB2_efi64_st, multiboot2_tag_efi64_t, pointer);
    OFFSET(MB2_efi64_ih, multiboot2_tag_efi64_ih_t, pointer);
    BLANK();

    OFFSET(DOMAIN_vm_assist, struct domain, vm_assist);
}
