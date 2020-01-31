use std::mem::size_of;

use scroll::{ctx, Endian, Pread, LE};

use crate::constant::IMAGE_DIRECTORY_ENTRY_IMPORT;
use crate::headers::SectionHeader;
use crate::Executable;

#[derive(Debug)]
pub struct ImportFunction {
    address: u64,
    hint: Option<u16>,
    name: String,
}

impl ImportFunction {
    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn hint(&self) -> Option<u16> {
        self.hint
    }

    pub fn name(&self) -> String {
        self.name.to_owned()
    }
}

#[derive(Debug)]
pub struct ImageImportByName {
    hint: Option<u16>,
    name: String,
}

impl<'a> ctx::TryFromCtx<'a, Endian> for ImageImportByName {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], _endian: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let hint = src.gread_with::<u16>(offset, LE)?;
        let name = src.gread::<&str>(offset)?;

        Ok((ImageImportByName { hint: Some(hint), name: name.to_owned() }, *offset))
    }
}

#[derive(Clone, Copy, Debug, Pread)]
pub struct ImageThunkData32 {
    u1: u32,
}

impl ImageThunkData32 {
    pub fn forwarder_string(&self) -> u32 {
        self.u1
    }

    pub fn function(&self) -> u32 {
        self.u1
    }

    pub fn ordinal(&self) -> u32 {
        self.u1
    }

    pub fn address_of_data(&self) -> u32 {
        self.u1
    }
}

#[derive(Clone, Copy, Debug, Pread)]
pub struct ImageThunkData64 {
    u1: u64,
}

impl ImageThunkData64 {
    pub fn forwarder_string(&self) -> u64 {
        self.u1
    }

    pub fn function(&self) -> u64 {
        self.u1
    }

    pub fn ordinal(&self) -> u64 {
        self.u1
    }

    pub fn address_of_data(&self) -> u64 {
        self.u1
    }
}

#[derive(Debug)]
pub struct ImportDescriptor {
    characteristics: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    address_of_name: u32, // raw data (name ptr)
    name: String,
    first_thunk: u32,
    functions: Option<Vec<ImportFunction>>,
}

impl<'a> ctx::TryFromCtx<'a, Endian> for ImportDescriptor {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], _endian: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let characteristics = src.gread_with::<u32>(offset, LE)?;
        let time_date_stamp = src.gread_with::<u32>(offset, LE)?;
        let forwarder_chain = src.gread_with::<u32>(offset, LE)?;
        let address_of_name = src.gread_with::<u32>(offset, LE)?;
        let first_thunk = src.gread_with::<u32>(offset, LE)?;

        Ok((
            ImportDescriptor {
                characteristics,
                time_date_stamp,
                forwarder_chain,
                address_of_name,
                name: "".to_string(),
                first_thunk,
                functions: None,
            },
            *offset,
        ))
    }
}

impl ImportDescriptor {
    pub fn characteristics(&self) -> u32 {
        self.characteristics
    }

    pub fn first_thunk(&self) -> u32 {
        self.first_thunk
    }

    pub fn forwarder_chain(&self) -> u32 {
        self.forwarder_chain
    }

    pub fn original_first_thunk(&self) -> u32 {
        self.characteristics
    }

    pub fn name(&self) -> String {
        self.name.to_owned()
    }

    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }

    pub fn functions(&self) -> Vec<&ImportFunction> {
        self.functions.as_ref().unwrap().iter().map(|w| w).collect()
    }
}

#[derive(Debug)]
pub struct ImportContainer {
    descriptors: Vec<ImportDescriptor>,
}

impl ImportContainer {
    pub fn parse(executable: &Executable) -> Result<Option<Self>, failure::Error> {
        let data_directory = executable.optional_header().unwrap().data_directories()[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
        if data_directory.size() == 0 {
            return Ok(None);
        }

        let section = match executable.in_section(data_directory) {
            Some(section) => section,
            None => {
                let msg = "Failed to read import descriptor";
                return Err(failure::err_msg(msg));
            }
        };

        let mut offset = executable.rva_to_file_pointer(data_directory.virtual_address(), section);
        let mut vector: Vec<ImportDescriptor> = Vec::new();

        // see: https://gist.github.com/huonw/8435502
        while {
            let mut descriptor = executable.buffer().gread_with::<ImportDescriptor>(&mut offset, LE).map_err(|_| {
                let msg = format!("Failed to read the IMAGE_IMPORT_DESCRIPTOR at {:#010X}", offset);
                return failure::err_msg(msg);
            })?;
            let next_addr = descriptor.original_first_thunk();

            if descriptor.original_first_thunk() != 0 {
                let address = executable.rva_to_file_pointer(descriptor.address_of_name, section);
                match executable.buffer().pread::<&str>(address) {
                    Ok(name) => descriptor.name = name.to_owned(),
                    Err(_) => {
                        let msg = format!("Failed to read the name of IMAGE_IMPORT_DESCRIPTOR at {:#010X}", address);
                        return Err(failure::err_msg(msg));
                    }
                };

                if executable.is_x64() {
                    let address = executable.rva_to_file_pointer(descriptor.first_thunk(), section);
                    let iat = ImportContainer::create_import_address_table_64(&executable, address)?;

                    let address = executable.rva_to_file_pointer(descriptor.original_first_thunk(), section);
                    let int = ImportContainer::create_import_name_table_64(&executable, section, address)?;

                    let mut functions: Vec<ImportFunction> = Vec::new();

                    for i in 0..iat.len() {
                        let address = iat[i as usize];
                        let by_name = &int[i as usize];

                        functions.push(ImportFunction {
                            address,
                            name: by_name.name.to_owned(),
                            hint: by_name.hint,
                        });
                    }

                    descriptor.functions = Some(functions);
                } else {
                    let address = executable.rva_to_file_pointer(descriptor.first_thunk(), section);
                    let iat = ImportContainer::create_import_address_table_32(&executable, address)?;

                    let address = executable.rva_to_file_pointer(descriptor.original_first_thunk(), section);
                    let int = ImportContainer::create_import_name_table_32(&executable, section, address)?;

                    let mut functions: Vec<ImportFunction> = Vec::new();

                    for i in 0..iat.len() {
                        let address = iat[i as usize];
                        let by_name = &int[i as usize];

                        functions.push(ImportFunction {
                            address,
                            name: by_name.name.to_owned(),
                            hint: by_name.hint,
                        });
                    }

                    descriptor.functions = Some(functions);
                }

                vector.push(descriptor);
            }

            next_addr != 0
        } {}

        Ok(Some(ImportContainer { descriptors: vector }))
    }

    pub fn descriptors(&self) -> Vec<&ImportDescriptor> {
        self.descriptors.iter().map(|w| w).collect()
    }

    fn create_import_address_table_32(executable: &Executable, first_address: usize) -> Result<Vec<u64>, failure::Error> {
        // first address
        let mut address = first_address;
        let mut vector: Vec<u64> = Vec::new();
        let address_size = size_of::<ImageThunkData32>();

        while {
            let thunk = executable.buffer().pread_with::<ImageThunkData32>(address, LE).map_err(|_| {
                let msg = format!("Failed to read IMAGE_THUNK_DATA64 at {:#010X}", address);
                return failure::err_msg(msg);
            })?;

            if thunk.function() != 0 {
                if ImportContainer::snap_by_ordinal32(thunk.ordinal()) {
                    vector.push(ImportContainer::ordinal32(thunk.function()) as u64);
                } else {
                    vector.push(thunk.function() as u64); // absolute address
                }

                address = address + address_size;
            }

            thunk.function() != 0
        } {}

        Ok(vector)
    }

    fn create_import_address_table_64(executable: &Executable, first_address: usize) -> Result<Vec<u64>, failure::Error> {
        // first address
        let mut address = first_address;
        let mut vector: Vec<u64> = Vec::new();
        let address_size = size_of::<ImageThunkData64>();

        while {
            let thunk = executable.buffer().pread_with::<ImageThunkData64>(address, LE).map_err(|_| {
                let msg = format!("Failed to read IMAGE_THUNK_DATA64 at {:#010X}", address);
                return failure::err_msg(msg);
            })?;

            if thunk.function() != 0 {
                if ImportContainer::snap_by_ordinal64(thunk.ordinal()) {
                    vector.push(ImportContainer::ordinal64(thunk.function()));
                } else {
                    vector.push(thunk.function()); // absolute address
                }

                address = address + address_size;
            }

            thunk.function() != 0
        } {}

        Ok(vector)
    }

    fn create_import_name_table_32(executable: &Executable, section: &SectionHeader, first_address: usize) -> Result<Vec<ImageImportByName>, failure::Error> {
        // first address
        let mut address = first_address;
        let mut vector: Vec<ImageImportByName> = Vec::new();
        let address_size = size_of::<ImageThunkData32>();

        while {
            let thunk = executable.buffer().pread_with::<ImageThunkData32>(address, LE).map_err(|_| {
                let msg = format!("Failed to read IMAGE_THUNK_DATA64 at {:#010X}", address);
                return failure::err_msg(msg);
            })?;

            if thunk.function() != 0 {
                if ImportContainer::snap_by_ordinal32(thunk.function()) {
                    vector.push(ImageImportByName {
                        name: format!("(Ordinal {})", ImportContainer::ordinal32(thunk.function())),
                        hint: None,
                    });
                } else {
                    let addr_of_name = executable.rva_to_file_pointer(thunk.address_of_data() as u32, section);
                    let by_name = executable.buffer().pread_with::<ImageImportByName>(addr_of_name, LE).map_err(|_| {
                        let msg = format!("Failed to read IMAGE_IMPORT_BY_NAME at {:#010X}", addr_of_name);
                        return failure::err_msg(msg);
                    })?;

                    vector.push(by_name);
                }

                address = address + address_size;
            }

            thunk.function() != 0
        } {}

        Ok(vector)
    }

    fn create_import_name_table_64(executable: &Executable, section: &SectionHeader, first_address: usize) -> Result<Vec<ImageImportByName>, failure::Error> {
        // first address
        let mut address = first_address;
        let mut vector: Vec<ImageImportByName> = Vec::new();
        let address_size = size_of::<ImageThunkData64>();

        while {
            let thunk: ImageThunkData64 = executable.buffer().pread_with::<ImageThunkData64>(address, LE).map_err(|_| {
                let msg = format!("Failed to read IMAGE_THUNK_DATA64 at {:#010X}", address);
                return failure::err_msg(msg);
            })?;

            if thunk.function() != 0 {
                if ImportContainer::snap_by_ordinal64(thunk.function()) {
                    vector.push(ImageImportByName {
                        name: format!("(Ordinal {})", ImportContainer::ordinal64(thunk.function())),
                        hint: None,
                    });
                } else {
                    let addr_of_name = executable.rva_to_file_pointer(thunk.address_of_data() as u32, section);
                    let by_name = executable.buffer().pread_with::<ImageImportByName>(addr_of_name, LE).map_err(|_| {
                        let msg = format!("Failed to read IMAGE_IMPORT_BY_NAME at {:#010X}", addr_of_name);
                        return failure::err_msg(msg);
                    })?;

                    vector.push(by_name);
                }

                address = address + address_size;
            }

            thunk.function() != 0
        } {}

        Ok(vector)
    }

    fn ordinal32(ordinal: u32) -> u32 {
        ordinal & 0xffff
    }

    fn ordinal64(ordinal: u64) -> u64 {
        ordinal & 0xffff
    }

    fn snap_by_ordinal32(ordinal: u32) -> bool {
        ordinal & 0x80000000 != 0
    }

    fn snap_by_ordinal64(ordinal: u64) -> bool {
        ordinal & 0x8000000000000000 != 0
    }
}
