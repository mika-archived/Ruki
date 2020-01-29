use std::mem::size_of;

use scroll::{ctx, Endian, Pread, LE};

use crate::constant::{IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DIRECTORY_ENTRY_DEBUG};
use crate::directories::DebugDirectory;
use crate::guid::GUID;
use crate::Executable;

#[repr(C)]
#[derive(Debug, Default)]
pub struct CodeView {
    format: u32,
    guid: GUID,
    age: u32,
    path: String,
}

impl CodeView {
    pub fn age(&self) -> u32 {
        self.age
    }

    pub fn format(&self) -> u32 {
        self.format
    }

    pub fn guid(&self) -> &GUID {
        &self.guid
    }

    pub fn path(&self) -> String {
        self.path.to_owned()
    }
}

impl<'a> ctx::TryFromCtx<'a, Endian> for CodeView {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], _endian: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let format = src.gread_with::<u32>(offset, LE)?;
        let guid = src.gread_with::<GUID>(offset, LE)?;
        let age = src.gread_with::<u32>(offset, LE)?;
        let path = src.gread::<&str>(offset)?;

        Ok((
            CodeView {
                format,
                guid,
                age,
                path: path.to_string(),
            },
            *offset,
        ))
    }
}

#[derive(Debug, Default)]
pub struct DebugContainer {
    directory: DebugDirectory,
    code_view: Option<CodeView>,
}

impl DebugContainer {
    pub fn parse(executable: &Executable) -> Result<Option<Vec<Self>>, failure::Error> {
        let data_directory = executable.optional_header().unwrap().data_directories()[IMAGE_DIRECTORY_ENTRY_DEBUG as usize];
        let debug_dir_size = data_directory.size();

        if debug_dir_size == 0 {
            return Ok(None);
        }

        let section = match executable.in_section(data_directory) {
            Some(section) => section,
            None => {
                let msg = "Failed to read debug directory";
                return Err(failure::err_msg(msg));
            }
        };

        let mut offset = executable.rva_to_file_pointer(data_directory.virtual_address(), section);
        let mut vector: Vec<DebugContainer> = Vec::new();
        let struct_size: u32 = size_of::<DebugDirectory>() as u32;

        for _ in 0..(debug_dir_size / struct_size) {
            let directory = DebugDirectory::parse(executable, &mut offset)?;

            match directory.r#type() {
                IMAGE_DEBUG_TYPE_CODEVIEW => {
                    let address: usize = executable.rva_to_file_pointer(directory.address_of_raw_data(), section);
                    let code_view = executable.buffer().pread_with::<CodeView>(address, LE).map_err(|_| {
                        let msg = format!("Failed to read XXX_CODE_VIEW struct at {:X}", offset);
                        return failure::err_msg(msg);
                    })?;

                    vector.push(DebugContainer { directory, code_view: Some(code_view) });
                }
                _ => vector.push(DebugContainer { directory, code_view: None }),
            }
        }

        Ok(Some(vector))
    }

    pub fn code_view(&self) -> Option<&CodeView> {
        self.code_view.as_ref()
    }

    pub fn directory(&self) -> DebugDirectory {
        self.directory
    }
}
