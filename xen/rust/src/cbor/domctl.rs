use core::ptr::NonNull;

use ciborium_io::Write;
use enumflags2::BitFlags;
use uuid::Uuid;

use crate::cbor::abi::{DomainState, DomainStatus, DomainVCpuInfo, GuestMemory};

// Opaque struct for pointer
#[repr(C)]
struct Domain(());

unsafe extern "C" {
    unsafe fn get_domain_by_id(domid: u16) -> *mut Domain;
    unsafe fn rust_stub_put_domain(domain: *mut Domain);

    unsafe fn getdomaininfo(domain: *mut Domain, info: &mut XenDomctlGetDomainInfo);

}

#[derive(Clone, Copy)]
#[enumflags2::bitflags]
#[repr(u32)]
enum XenDomInf {
    Dying = 1 << 0,
    HvmGuest = 1 << 1,
    Shutdown = 1 << 2,
    Paused = 1 << 3,
    Blocked = 1 << 4,
    Running = 1 << 5,
    Debugged = 1 << 6,
    XsDomain = 1 << 7,
    Hap = 1 << 8,
}

#[derive(Default)]
#[repr(C)]
pub struct ArchConfigX86 {
    emulation_flags: u32,
    misc_flags: u32,
}

#[derive(Default)]
#[repr(C)]
struct XenDomctlGetDomainInfo {
    domain: u16,
    _pad1: u16,
    flags: BitFlags<XenDomInf>,
    tot_pages: u64,
    max_pages: u64,
    outstanding_pages: u64,
    shr_pages: u64,
    paged_pages: u64,
    shared_info_frame: u64,
    cpu_time: u64,
    nr_online_vcpus: u32,
    max_vcpu_id: u32,
    ssidref: u32,
    handle: Uuid,
    cpupool: u32,
    gpaddr_bits: u8,
    pad2: [u8; 7],
    arch_config: ArchConfigX86,
}

pub fn get_domain_status<W>(
    output: &mut W,
    domid: u16,
    dump_vcpus: bool,
) -> Result<(), &'static str>
where
    W: Write,
    W::Error: core::fmt::Debug,
{
    let vcpus_buffer = [DomainVCpuInfo::default(); 16];
    let vcpus = dump_vcpus.then(|| vcpus_buffer.as_slice());

    let mut domain = NonNull::new(unsafe { get_domain_by_id(domid) }).ok_or("No such domain")?;

    // Use getdomaininfo for now
    let mut info = XenDomctlGetDomainInfo::default();
    unsafe { getdomaininfo(domain.as_mut(), &mut info) };

    let status = DomainStatus {
        dying: info.flags.contains(XenDomInf::Dying),
        memory: GuestMemory {
            tot_pages: info.tot_pages,
            max_pages: info.max_pages,
            outstanding_pages: info.outstanding_pages,
            shr_pages: info.shr_pages,
            paged_pages: info.paged_pages,
            shared_info_frame: info.shared_info_frame,
        },
        vcpus,
        max_vcpu_id: None,
        state: if info.flags.contains(XenDomInf::Running) {
            DomainState::Running
        } else {
            DomainState::Shutdown(0 /* TODO */)
        },
    };

    unsafe { rust_stub_put_domain(domain.as_mut()) };

    ciborium::into_writer(&status, output).map_err(|_| "Unable to write buffer")
}
