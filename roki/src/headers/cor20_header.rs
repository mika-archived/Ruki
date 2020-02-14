use scroll::{Pread, LE};

use crate::constant::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;
use crate::directories::DataDirectory;
use crate::Executable;

// .NET CLR Header / This header may be change in the future.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pread)]
pub struct Cor20Header {
    cb: u32,
    major_runtime_version: u16,
    minor_runtime_version: u16,
    meta_data: DataDirectory,
    flags: u32,
    entry_point_rva: u32, // a.k.a entry_point_token
    resources: DataDirectory,
    strong_name_signature: DataDirectory,
    code_manager_table: DataDirectory,
    v_table_fixups: DataDirectory,
    export_address_table_jumps: DataDirectory,
    managed_native_header: DataDirectory,
}

impl Cor20Header {
    pub fn parse(executable: &Executable) -> Result<Option<Self>, failure::Error> {
        let com_descriptor = executable.optional_header().unwrap().data_directories()[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR as usize];
        let com_dir_size = com_descriptor.size();

        if com_dir_size == 0 {
            return Ok(None);
        }

        let section = match executable.in_section(com_descriptor) {
            Some(section) => section,
            None => {
                let msg = "Failed to read debug directory data";
                return Err(failure::err_msg(msg));
            }
        };

        let offset = executable.rva_to_file_pointer(com_descriptor.virtual_address(), section);
        let cor20_header = executable.buffer().pread_with::<Cor20Header>(offset, LE).map_err(|_| {
            let msg = format!("Failed to read the IMAGE_COR20_HEADER at {:#X}", offset);
            return failure::err_msg(msg);
        })?;

        Ok(Some(cor20_header))
    }

    pub fn cb(&self) -> u32 {
        self.cb
    }

    pub fn code_manager_table(&self) -> &DataDirectory {
        &self.code_manager_table
    }

    pub fn entry_point_rva(&self) -> u32 {
        self.entry_point_rva
    }

    pub fn entry_point_token(&self) -> u32 {
        self.entry_point_rva
    }

    pub fn export_address_table_jumps(&self) -> &DataDirectory {
        &self.export_address_table_jumps
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn major_runtime_version(&self) -> u16 {
        self.major_runtime_version
    }

    pub fn managed_native_header(&self) -> &DataDirectory {
        &self.managed_native_header
    }

    pub fn meta_data(&self) -> &DataDirectory {
        &self.meta_data
    }

    pub fn minor_runtime_version(&self) -> u16 {
        self.minor_runtime_version
    }

    pub fn resources(&self) -> &DataDirectory {
        &self.resources
    }

    pub fn strong_name_signature(&self) -> &DataDirectory {
        &self.strong_name_signature
    }

    pub fn v_table_fixups(&self) -> &DataDirectory {
        &self.v_table_fixups
    }
}
