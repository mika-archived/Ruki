use scroll::{Pread, LE};

use crate::Executable;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pread)]
pub struct DebugDirectory {
    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_debug_directory
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    r#type: u32,
    size_of_data: u32,
    address_of_raw_data: u32,
    pointer_to_raw_data: u32,
}

impl DebugDirectory {
    pub fn parse(executable: &Executable, mut offset: &mut usize) -> Result<DebugDirectory, failure::Error> {
        let debug_directory = executable.buffer().gread_with::<DebugDirectory>(&mut offset, LE).map_err(|_| {
            let msg = format!("Failed to read the IMAGE_DEBUG_DIRECTORY at {:#X}", offset);
            return failure::err_msg(msg);
        })?;

        Ok(debug_directory)
    }

    pub fn address_of_raw_data(&self) -> u32 {
        self.address_of_raw_data
    }

    pub fn characteristics(&self) -> u32 {
        self.characteristics
    }

    pub fn major_version(&self) -> u16 {
        self.major_version
    }

    pub fn minor_version(&self) -> u16 {
        self.minor_version
    }

    pub fn pointer_to_raw_data(&self) -> u32 {
        self.pointer_to_raw_data
    }

    pub fn size_of_data(&self) -> u32 {
        self.size_of_data
    }

    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }

    pub fn r#type(&self) -> u32 {
        self.r#type
    }
}
