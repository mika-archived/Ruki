use scroll::{ctx, Endian, Pread, LE};

use crate::headers::SectionHeader;
use crate::Executable;

#[derive(Debug, Default)]
pub struct ExportDirectory {
    // see WinNT.h at Windows 10.0.18326 #17982-
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    address_of_name: u32, // raw data (name ptr)
    name: String,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

impl<'a> ctx::TryFromCtx<'a, Endian> for ExportDirectory {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], _endian: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let characteristics = src.gread_with::<u32>(offset, LE)?;
        let time_date_stamp = src.gread_with::<u32>(offset, LE)?;
        let major_version = src.gread_with::<u16>(offset, LE)?;
        let minor_version = src.gread_with::<u16>(offset, LE)?;
        let address_of_name = src.gread_with::<u32>(offset, LE)?;
        let base = src.gread_with::<u32>(offset, LE)?;
        let number_of_functions = src.gread_with::<u32>(offset, LE)?;
        let number_of_names = src.gread_with::<u32>(offset, LE)?;
        let address_of_functions = src.gread_with::<u32>(offset, LE)?;
        let address_of_names = src.gread_with::<u32>(offset, LE)?;
        let address_of_name_ordinals = src.gread_with::<u32>(offset, LE)?;

        Ok((
            ExportDirectory {
                characteristics,
                time_date_stamp,
                major_version,
                minor_version,
                name: "".to_string(),
                address_of_name,
                base,
                number_of_functions,
                number_of_names,
                address_of_functions,
                address_of_names,
                address_of_name_ordinals,
            },
            *offset,
        ))
    }
}

impl ExportDirectory {
    pub fn parse(executable: &Executable, section: &SectionHeader, offset: usize) -> Result<ExportDirectory, failure::Error> {
        let mut export_directory = executable.buffer().pread_with::<ExportDirectory>(offset, LE).map_err(|_| {
            let msg = format!("Failed to read the IMAGE_EXPORT_DIRECTORY at {:#X}", offset);
            return failure::err_msg(msg);
        })?;

        // try to fill the name of this struct
        let address = executable.rva_to_file_pointer(export_directory.address_of_name, section); // read name from .idata section
        match executable.buffer().pread::<&str>(address) {
            Ok(name) => export_directory.name = name.to_owned(),
            Err(_) => {
                let msg = format!("Failed to read the name of IMAGE_EXPORT_DIRECTORY at {:#X}", address);
                return Err(failure::err_msg(msg));
            }
        };

        Ok(export_directory)
    }

    pub fn address_of_functions(&self) -> u32 {
        self.address_of_functions
    }

    pub fn address_of_name_ordinals(&self) -> u32 {
        self.address_of_name_ordinals
    }

    pub fn address_of_names(&self) -> u32 {
        self.address_of_names
    }

    pub fn base(&self) -> u32 {
        self.base
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

    pub fn name(&self) -> String {
        self.name.to_string()
    }

    pub fn number_of_functions(&self) -> u32 {
        self.number_of_functions
    }

    pub fn number_of_names(&self) -> u32 {
        self.number_of_names
    }

    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }
}
