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
}
