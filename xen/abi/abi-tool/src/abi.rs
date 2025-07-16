pub trait XenABI {
    fn get_register_name(id: u8) -> &'static str;
}

pub struct Amd64ABI;

impl XenABI for Amd64ABI {
    fn get_register_name(id: u8) -> &'static str {
        match id {
            0 => "rax",
            1 => "rdi",
            2 => "rsi",
            3 => "r8",
            4 => "r9",
            5 => "r10",
            6 => "r11",
            7 => "r12",
            8 => "r13",

            _ => panic!("Unexpected register id: {id}"),
        }
    }
}
