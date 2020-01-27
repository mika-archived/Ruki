use std::convert::TryInto;

use scroll::{ctx, Endian, Pread, LE};

use super::Container;
use crate::guid::GUID;

const DEBUG_INDEX: usize = 6;
const BYTES_OF_DEBUG_DIRECTORY: u32 = 28;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 0x2;

#[derive(Debug, Default)]
pub struct DebugInformation {
    directory: DebugDirectory,
    code_view: Option<CodeView>,
    // are we support FPO struct?
}

impl DebugInformation {
    pub fn parse(container: &Container) -> Result<Vec<Self>, failure::Error> {
        let data_directory = container.optional_header().unwrap().data_directories()[DEBUG_INDEX];
        let debug_dir_size = data_directory.size();

        if debug_dir_size == 0 {
            return Ok(vec![]);
        }

        let section = match container.in_section(data_directory) {
            Some(section) => section,
            None => {
                let msg = "Failed to read debug directory data";
                return Err(failure::err_msg(msg));
            }
        };

        let mut offset = container.rva_to_file_pointer(data_directory, section);
        let mut vector: Vec<DebugInformation> = Vec::new();

        for _ in 0..(debug_dir_size / BYTES_OF_DEBUG_DIRECTORY) {
            let directory = DebugDirectory::parse(container, &mut offset)?;

            match directory.r#type() {
                IMAGE_DEBUG_TYPE_CODEVIEW => {
                    let address: usize = directory.pointer_to_raw_data().try_into().unwrap();
                    let code_view = container.buffer().pread_with::<CodeView>(address, LE).map_err(|_| {
                        let msg = format!("Failed to read XXX_CODE_VIEW struct at {:X}", offset);
                        return failure::err_msg(msg);
                    })?;

                    vector.push(DebugInformation { directory, code_view: Some(code_view) });
                }
                _ => vector.push(DebugInformation { directory, code_view: None }),
            }
        }

        Ok(vector)
    }

    pub fn code_view(&self) -> Option<&CodeView> {
        self.code_view.as_ref()
    }

    pub fn directory(&self) -> DebugDirectory {
        self.directory
    }
}

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
    pub fn parse(container: &Container, mut offset: &mut usize) -> Result<DebugDirectory, failure::Error> {
        let debug_directory = container.buffer().gread_with::<DebugDirectory>(&mut offset, LE).map_err(|_| {
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
