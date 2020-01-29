use scroll::{Pread, LE};

use crate::Executable;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pread)]
pub struct FileHeader {
    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
    machine: u16,
    number_of_sections: u16,
    time_date_stamps: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

impl FileHeader {
    pub fn parse(executable: &mut Executable, mut offset: &mut usize) -> Result<FileHeader, failure::Error> {
        *offset += executable.dos_header().unwrap().addr_of_nt_header() as usize;
        let signature = executable.buffer().gread_with::<u32>(&mut offset, LE).map_err(|_| {
            let msg = format!("Could not parse PE header at {:#X}", offset);
            return failure::err_msg(msg);
        })?;

        if signature != 0x00004550 {
            return Ok(FileHeader { ..Default::default() });
        }

        let file_header = executable.buffer().gread_with::<FileHeader>(&mut offset, LE).map_err(|_| {
            let msg = format!("Failed to read the FILE_HEADER at {:#X}", offset);
            return failure::err_msg(msg);
        })?;

        return Ok(file_header);
    }

    // getters
    pub fn characteristics(&self) -> u16 {
        self.characteristics
    }

    pub fn is_portable_executable(&self) -> bool {
        self.machine() != 0
    }

    pub fn machine(&self) -> u16 {
        self.machine
    }

    pub fn number_of_sections(&self) -> u16 {
        self.number_of_sections
    }

    pub fn number_of_symbols(&self) -> u32 {
        self.number_of_symbols // always 0
    }

    pub fn pointer_to_symbol_table(&self) -> u32 {
        self.pointer_to_symbol_table // always 0
    }

    pub fn size_of_optional_header(&self) -> u16 {
        self.size_of_optional_header
    }

    pub fn time_date_stamps(&self) -> u32 {
        self.time_date_stamps
    }
}
