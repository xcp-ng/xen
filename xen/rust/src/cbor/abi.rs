use core::{num::NonZeroU32, ops::Not};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize)]
pub struct HypercallError {
    /* FIXME: use a string for now, consider more structured errors in the future */
    pub message: &'static str,
}

/*
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum ShutdownReason {
    PowerOff,
    Reboot,
    Suspend,
    Crash,
    Watchdog,
    #[serde(rename = "soft_reset")]
    SoftReset,
}
*/

#[derive(Serialize)]
#[serde(rename = "lowercase")]
pub enum DomainState {
    Running,
    Shutdown(u8),
}

#[derive(Serialize)]
#[serde(rename = "lowercase")]
pub enum GuestType {
    Hvm { hvm: bool, shadow: bool },
    Pv {},
}

#[derive(Serialize)]
pub struct GuestMemory {
    pub tot_pages: u64,
    pub max_pages: u64,
    pub outstanding_pages: u64,
    pub shr_pages: u64,
    pub paged_pages: u64,
    pub shared_info_frame: u64,
}

#[derive(Clone, Copy, Default, Serialize)]
pub struct DomainVCpuInfo {
    pub online: bool,
    #[serde(skip_serializing_if = "<&bool>::not")]
    pub blocked: bool,
    pub running: bool,
    pub time: u64,
    pub cpu: u32,
}

#[derive(Serialize)]
pub struct DomainStatus<'a> {
    #[serde(skip_serializing_if = "<&bool>::not")]
    pub dying: bool,

    pub state: DomainState,
    pub memory: GuestMemory,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_vcpu_id: Option<NonZeroU32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcpus: Option<&'a [DomainVCpuInfo]>,
}

#[derive(Serialize)]
pub struct X86DomainInfo {
    pub emulation_flags: u32,
    pub misc_flags: u32,
}

#[derive(Serialize)]
pub struct DomainInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<Uuid>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssidref: Option<NonZeroU32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpupool: Option<NonZeroU32>,

    pub gpaddr_bits: u8,

    pub guest_type: GuestType,
    pub state: DomainState,

    pub arch: X86DomainInfo,
}

#[derive(Deserialize)]
pub enum CborHypercall {
    #[serde(rename = "domctl.GetDomainState")]
    GetDomainState {
        domid: u16,
        #[serde(default)]
        dump_vcpus: bool,
    },

    #[serde(rename = "domctl.GetDomainInfo")]
    GetDomainInfo { domid: u16 },
}
