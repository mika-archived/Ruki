use std::convert::TryInto;

use crate::container::Container;
use crate::directories::DataDirectory;

use scroll::{Pread, LE};

const NUMBER_OF_DATA_DIRECTORIES: usize = 16;
const X64_MACHINE: u16 = 0x8664;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pread)]
pub struct OptionalHeader32 {
    // see: https://docs.microsoft.com/ja-jp/windows/win32/api/winnt/ns-winnt-image_optional_header32
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pread)]
pub struct OptionalHeader64 {
    // see: https://docs.microsoft.com/ja-jp/windows/win32/api/winnt/ns-winnt-image_optional_header64
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[derive(Debug)]
pub struct OptionalHeader {
    // this field is private, worked as accessor as x86/x64 properties
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [DataDirectory; NUMBER_OF_DATA_DIRECTORIES],
}

impl OptionalHeader {
    pub fn parse(container: &mut Container, mut offset: &mut usize) -> Result<OptionalHeader, failure::Error> {
        let machine = container.file_header().unwrap().machine();

        if machine == X64_MACHINE {
            let optional_header = container.buffer().gread_with::<OptionalHeader64>(&mut offset, LE).map_err(|_| {
                let msg = format!("Failed to read the OPTIONAL_HEADER_64 at {:#X}", offset);
                return failure::err_msg(msg);
            })?;

            let data_directory = OptionalHeader::parse_data_directories(container, &mut offset)?;

            return Ok(OptionalHeader {
                magic: optional_header.magic,
                major_linker_version: optional_header.major_linker_version,
                minor_linker_version: optional_header.minor_linker_version,
                size_of_code: optional_header.size_of_code,
                size_of_initialized_data: optional_header.size_of_initialized_data,
                size_of_uninitialized_data: optional_header.size_of_uninitialized_data,
                address_of_entry_point: optional_header.address_of_entry_point,
                base_of_code: optional_header.base_of_code,
                base_of_data: 0,
                image_base: optional_header.image_base,
                section_alignment: optional_header.section_alignment,
                file_alignment: optional_header.file_alignment,
                major_operating_system_version: optional_header.major_operating_system_version,
                minor_operating_system_version: optional_header.minor_operating_system_version,
                major_image_version: optional_header.major_image_version,
                minor_image_version: optional_header.minor_image_version,
                major_subsystem_version: optional_header.major_subsystem_version,
                minor_subsystem_version: optional_header.minor_subsystem_version,
                win32_version_value: optional_header.win32_version_value,
                size_of_image: optional_header.size_of_image,
                size_of_headers: optional_header.size_of_headers,
                checksum: optional_header.checksum,
                subsystem: optional_header.subsystem,
                dll_characteristics: optional_header.dll_characteristics,
                size_of_stack_reserve: optional_header.size_of_stack_reserve,
                size_of_stack_commit: optional_header.size_of_stack_commit,
                size_of_heap_reserve: optional_header.size_of_heap_reserve,
                size_of_heap_commit: optional_header.size_of_heap_commit,
                loader_flags: optional_header.loader_flags,
                number_of_rva_and_sizes: optional_header.number_of_rva_and_sizes,
                data_directory,
            });
        } else {
            let optional_header = container.buffer().gread_with::<OptionalHeader32>(&mut offset, LE).map_err(|_| {
                let msg = format!("Failed to read the OPTIONAL_HEADER_64 at {:#X}", offset);
                return failure::err_msg(msg);
            })?;

            let data_directory = OptionalHeader::parse_data_directories(container, &mut offset)?;

            return Ok(OptionalHeader {
                magic: optional_header.magic,
                major_linker_version: optional_header.major_linker_version,
                minor_linker_version: optional_header.minor_linker_version,
                size_of_code: optional_header.size_of_code,
                size_of_initialized_data: optional_header.size_of_initialized_data,
                size_of_uninitialized_data: optional_header.size_of_uninitialized_data,
                address_of_entry_point: optional_header.address_of_entry_point,
                base_of_code: optional_header.base_of_code,
                base_of_data: optional_header.base_of_data,
                image_base: optional_header.image_base as u64,
                section_alignment: optional_header.section_alignment,
                file_alignment: optional_header.file_alignment,
                major_operating_system_version: optional_header.major_operating_system_version,
                minor_operating_system_version: optional_header.minor_operating_system_version,
                major_image_version: optional_header.major_image_version,
                minor_image_version: optional_header.minor_image_version,
                major_subsystem_version: optional_header.major_subsystem_version,
                minor_subsystem_version: optional_header.minor_subsystem_version,
                win32_version_value: optional_header.win32_version_value,
                size_of_image: optional_header.size_of_image,
                size_of_headers: optional_header.size_of_headers,
                checksum: optional_header.checksum,
                subsystem: optional_header.subsystem,
                dll_characteristics: optional_header.dll_characteristics,
                size_of_stack_reserve: optional_header.size_of_stack_reserve as u64,
                size_of_stack_commit: optional_header.size_of_stack_commit as u64,
                size_of_heap_reserve: optional_header.size_of_heap_reserve as u64,
                size_of_heap_commit: optional_header.size_of_heap_commit as u64,
                loader_flags: optional_header.loader_flags,
                number_of_rva_and_sizes: optional_header.number_of_rva_and_sizes,
                data_directory,
            });
        }
    }

    // TODO: see number_of_rva_and_sizes for the feature
    fn parse_data_directories(container: &mut Container, mut offset: &mut usize) -> Result<[DataDirectory; NUMBER_OF_DATA_DIRECTORIES], failure::Error> {
        fn read_dictionary_data(container: &Container, mut offset: &mut usize) -> Result<DataDirectory, failure::Error> {
            container.buffer().gread_with::<DataDirectory>(&mut offset, LE).map_err(|_| {
                let msg = format!("Failed to read the DATA_DIRECTORY at {:#X}", offset);
                return failure::err_msg(msg);
            })
        }

        let export = read_dictionary_data(container, &mut offset)?;
        let import = read_dictionary_data(container, &mut offset)?;
        let resource = read_dictionary_data(container, &mut offset)?;
        let exception = read_dictionary_data(container, &mut offset)?;
        let security = read_dictionary_data(container, &mut offset)?;
        let basereloc = read_dictionary_data(container, &mut offset)?;
        let debug = read_dictionary_data(container, &mut offset)?;
        let architecture = read_dictionary_data(container, &mut offset)?;
        let global_ptr = read_dictionary_data(container, &mut offset)?;
        let tls = read_dictionary_data(container, &mut offset)?;
        let load_config = read_dictionary_data(container, &mut offset)?;
        let bound_import = read_dictionary_data(container, &mut offset)?;
        let entry_iat = read_dictionary_data(container, &mut offset)?;
        let delay_import = read_dictionary_data(container, &mut offset)?;
        let com_descriptor = read_dictionary_data(container, &mut offset)?; // a.k.a .NET CLR Descriptor
        let reserved = read_dictionary_data(container, &mut offset)?;

        return Ok([
            export,
            import,
            resource,
            exception,
            security,
            basereloc,
            debug,
            architecture,
            global_ptr,
            tls,
            load_config,
            bound_import,
            entry_iat,
            delay_import,
            com_descriptor,
            reserved,
        ]);
    }

    // getters
    pub fn address_of_entry_point(&self) -> u32 {
        self.address_of_entry_point
    }

    pub fn base_of_code(&self) -> u32 {
        self.base_of_code
    }

    pub fn base_of_data(&self) -> u32 {
        self.base_of_data
    }

    pub fn checksum(&self) -> u32 {
        self.checksum
    }

    pub fn data_directories(&self) -> [&DataDirectory; NUMBER_OF_DATA_DIRECTORIES] {
        self.data_directory.iter().map(|s| s).collect::<Vec<&DataDirectory>>()[0..NUMBER_OF_DATA_DIRECTORIES].try_into().unwrap()
    }

    pub fn dll_characteristics(&self) -> u16 {
        self.dll_characteristics
    }

    pub fn file_alignment(&self) -> u32 {
        self.file_alignment
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn loader_flags(&self) -> u32 {
        self.loader_flags
    }

    pub fn magic(&self) -> u16 {
        self.magic
    }

    pub fn major_linker_version(&self) -> u8 {
        self.major_linker_version
    }

    pub fn major_image_version(&self) -> u16 {
        self.major_image_version
    }

    pub fn major_operating_system_version(&self) -> u16 {
        self.major_operating_system_version
    }

    pub fn major_subsystem_version(&self) -> u16 {
        self.major_subsystem_version
    }

    pub fn minor_linker_version(&self) -> u8 {
        self.minor_linker_version
    }

    pub fn minor_image_version(&self) -> u16 {
        self.minor_image_version
    }

    pub fn minor_operating_system_version(&self) -> u16 {
        self.minor_operating_system_version
    }

    pub fn minor_subsystem_version(&self) -> u16 {
        self.minor_subsystem_version
    }

    pub fn number_of_rva_and_sizes(&self) -> u32 {
        self.number_of_rva_and_sizes
    }

    pub fn section_alignment(&self) -> u32 {
        self.section_alignment
    }

    pub fn size_of_code(&self) -> u32 {
        self.size_of_code
    }

    pub fn size_of_headers(&self) -> u32 {
        self.size_of_headers
    }

    pub fn size_of_heap_commit(&self) -> u64 {
        self.size_of_heap_commit
    }

    pub fn size_of_heap_reserve(&self) -> u64 {
        self.size_of_heap_reserve
    }

    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    pub fn size_of_initialized_data(&self) -> u32 {
        self.size_of_initialized_data
    }

    pub fn size_of_stack_commit(&self) -> u64 {
        self.size_of_stack_commit
    }

    pub fn size_of_stack_reserve(&self) -> u64 {
        self.size_of_stack_reserve
    }

    pub fn size_of_uninitialized_data(&self) -> u32 {
        self.size_of_uninitialized_data
    }

    pub fn subsystem(&self) -> u16 {
        self.subsystem
    }

    pub fn win32_version_value(&self) -> u32 {
        self.win32_version_value
    }
}
