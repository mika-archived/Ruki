use scroll::{Pread, LE};

use super::Container;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pread)]
pub struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

impl SectionHeader {
    pub fn parse(container: &Container, mut offset: &mut usize) -> Result<Self, failure::Error> {
        let section_header = container.buffer().gread_with::<SectionHeader>(&mut offset, LE).map_err(|_| {
            let msg = format!("Failed to read SECTION_HEADER at {:#X}", offset);
            return failure::err_msg(msg);
        })?;

        return Ok(section_header);
    }

    pub fn characteristics(&self) -> u32 {
        self.characteristics
    }

    pub fn name(&self) -> String {
        self.name.iter().cloned().map(|s| s as char).collect::<String>()
    }

    pub fn number_of_linenumbers(&self) -> u16 {
        self.number_of_linenumbers
    }

    pub fn number_of_relocations(&self) -> u16 {
        self.number_of_relocations
    }

    pub fn pointer_to_linenumbers(&self) -> u32 {
        self.pointer_to_linenumbers
    }

    pub fn pointer_to_raw_data(&self) -> u32 {
        self.pointer_to_raw_data
    }

    pub fn pointer_to_relocations(&self) -> u32 {
        self.pointer_to_relocations
    }

    pub fn size_of_raw_data(&self) -> u32 {
        self.size_of_raw_data
    }

    pub fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    pub fn virtual_size(&self) -> u32 {
        self.virtual_size
    }
}
