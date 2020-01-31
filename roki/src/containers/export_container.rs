use std::collections::HashMap;
use std::mem::size_of;

use scroll::{Pread, LE};

use crate::constant::IMAGE_DIRECTORY_ENTRY_EXPORT;
use crate::directories::ExportDirectory;
use crate::Executable;

#[derive(Debug)]
pub struct ExportFunction {
    name: String,
    ordinal: u32,
    function: u32,
}

impl ExportFunction {
    pub fn function(&self) -> u32 {
        self.function
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }
}

#[derive(Debug)]
pub struct ExportContainer {
    directory: ExportDirectory,
    functions: Option<Vec<ExportFunction>>,
}

impl ExportContainer {
    pub fn parse(executable: &Executable) -> Result<Option<Self>, failure::Error> {
        let data_directory = executable.optional_header().unwrap().data_directories()[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        if data_directory.size() == 0 {
            return Ok(None);
        }

        let section = match executable.in_section(data_directory) {
            Some(section) => section,
            None => {
                let msg = "Failed to read export directory";
                return Err(failure::err_msg(msg));
            }
        };

        let address = executable.rva_to_file_pointer(data_directory.virtual_address(), section);
        let directory = ExportDirectory::parse(executable, section, address)?;

        if directory.number_of_functions() == 0 {
            // dead code?
            return Ok(Some(ExportContainer { directory, functions: None }));
        }

        // create name table
        let mut name_table: HashMap<u16, &str> = HashMap::new();
        for i in 0..directory.number_of_names() {
            let address = executable.rva_to_file_pointer(directory.address_of_name_ordinals() + i * (size_of::<u16>() as u32), section);
            let ordinal = executable.buffer().pread_with::<u16>(address, LE).map_err(|_| {
                let msg = format!("Failed to read ordinal at {:#X}", address);
                return failure::err_msg(msg);
            })?;

            let address = executable.rva_to_file_pointer(directory.address_of_names() + i * (size_of::<u32>() as u32), section);
            let name_ptr = executable.buffer().pread::<u32>(address).map_err(|_| {
                let msg = format!("Failed to read name pointer at {:#X}", address);
                return failure::err_msg(msg);
            })?;

            let address = executable.rva_to_file_pointer(name_ptr, section);
            let name = executable.buffer().pread::<&str>(address).map_err(|_| {
                let msg = format!("Failed to read name at {:#X}", address);
                return failure::err_msg(msg);
            })?;
            name_table.insert(ordinal, name);
        }

        let mut vector: Vec<ExportFunction> = Vec::new();
        for i in 0..directory.number_of_functions() {
            let address = executable.rva_to_file_pointer(directory.address_of_functions() + i * (size_of::<u32>() as u32), section);
            let function = executable.buffer().pread_with::<u32>(address, LE).map_err(|_| {
                let msg = format!("Failed to read function at {:#X}", address);
                return failure::err_msg(msg);
            })?;

            if address == 0 {
                continue;
            }

            let name = match name_table.get(&((i) as u16)) {
                Some(name) => name.to_string(),
                None => format!("(Ordinal {})", directory.base() + i),
            };

            vector.push(ExportFunction {
                name,
                ordinal: directory.base() + i,
                function,
            });
        }

        Ok(Some(ExportContainer { directory, functions: Some(vector) }))
    }

    pub fn directory(&self) -> &ExportDirectory {
        &self.directory
    }

    pub fn functions(&self) -> Option<Vec<&ExportFunction>> {
        match &self.functions {
            Some(functions) => Some(functions.iter().map(|w| w).collect()),
            None => None,
        }
    }
}
