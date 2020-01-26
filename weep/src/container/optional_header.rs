use std::convert::TryInto;

use super::data_directory::DataDirectory;
use super::Container;

const NUMBER_OF_DATA_DIRECTORIES: usize = 16;
const X64_MACHINE: u16 = 0x8664;

#[derive(Debug)]
pub struct OptionalHeader {
    // see: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    checksum: u32,
    data_directory: [DataDirectory; NUMBER_OF_DATA_DIRECTORIES],
    dll_characteristics: u16,
    file_alignment: u32,
    image_base: u64,
    loader_flags: u32,
    magic: u16,
    major_image_version: u16,
    major_linker_version: u8,
    major_operating_system_version: u16,
    major_subsystem_version: u16,
    minor_image_version: u16,
    minor_linker_version: u8,
    minor_operating_system_version: u16,
    minor_subsystem_version: u16,
    number_of_rva_and_sizes: u32,
    section_alignment: u32,
    size_of_code: u32,
    size_of_headers: u32,
    size_of_heap_commit: u64,
    size_of_heap_reserve: u64,
    size_of_image: u32,
    size_of_initialized_data: u32,
    size_of_stack_commit: u64,
    size_of_stack_reserve: u64,
    size_of_uninitialized_data: u32,
    subsystem: u16,
    win32_version_value: u32,
}

impl OptionalHeader {
    pub fn parse(container: &mut Container) -> Result<OptionalHeader, failure::Error> {
        let machine = container.file_header().unwrap().machine();

        let magic = container.read_as_u16()?;
        let major_linker_version = container.read_as_u8()?;
        let minor_linker_version = container.read_as_u8()?;
        let size_of_code = container.read_as_u32()?;
        let size_of_initialized_data = container.read_as_u32()?;
        let size_of_uninitialized_data = container.read_as_u32()?;
        let address_of_entry_point = container.read_as_u32()?;
        let base_of_code = container.read_as_u32()?;
        let base_of_data = match machine {
            X64_MACHINE => 0, // if machine is x64, this data is stripped
            _ => container.read_as_u32()?,
        };
        let image_base = match machine {
            X64_MACHINE => container.read_as_u64()?, // x64
            _ => container.read_as_u32()? as u64,
        };
        let section_alignment = container.read_as_u32()?;
        let file_alignment = container.read_as_u32()?;
        let major_operating_system_version = container.read_as_u16()?;
        let minor_operating_system_version = container.read_as_u16()?;
        let major_image_version = container.read_as_u16()?;
        let minor_image_version = container.read_as_u16()?;
        let major_subsystem_version = container.read_as_u16()?;
        let minor_subsystem_version = container.read_as_u16()?;
        let win32_version_value = container.read_as_u32()?;
        let size_of_image = container.read_as_u32()?;
        let size_of_headers = container.read_as_u32()?;
        let checksum = container.read_as_u32()?;
        let subsystem = container.read_as_u16()?;
        let dll_characteristics = container.read_as_u16()?;
        let size_of_stack_reserve = if machine == X64_MACHINE { container.read_as_u64()? } else { container.read_as_u32()? as u64 };
        let size_of_stack_commit = if machine == X64_MACHINE { container.read_as_u64()? } else { container.read_as_u32()? as u64 };
        let size_of_heap_reserve = if machine == X64_MACHINE { container.read_as_u64()? } else { container.read_as_u32()? as u64 };
        let size_of_heap_commit = if machine == X64_MACHINE { container.read_as_u64()? } else { container.read_as_u32()? as u64 };
        let loader_flags = container.read_as_u32()?;
        let number_of_rva_and_sizes = container.read_as_u32()?;

        fn create_directory_data(container: &mut Container) -> Result<DataDirectory, failure::Error> {
            Ok(DataDirectory::new(container.read_as_u32()?, container.read_as_u32()?))
        }

        // directory entries
        let export = create_directory_data(container)?;
        let import = create_directory_data(container)?;
        let resource = create_directory_data(container)?;
        let exception = create_directory_data(container)?;
        let security = create_directory_data(container)?;
        let basereloc = create_directory_data(container)?;
        let debug = create_directory_data(container)?;
        let architecture = create_directory_data(container)?;
        let global_ptr = create_directory_data(container)?;
        let tls = create_directory_data(container)?;
        let load_config = create_directory_data(container)?;
        let bound_import = create_directory_data(container)?;
        let entry_iat = create_directory_data(container)?;
        let delay_import = create_directory_data(container)?;
        let com_descriptor = create_directory_data(container)?; // a.k.a .NET CLR Descriptor
        let reserved = create_directory_data(container)?;

        Ok(OptionalHeader {
            address_of_entry_point,
            base_of_code,
            base_of_data,
            data_directory: [
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
            ],
            dll_characteristics,
            checksum,
            file_alignment,
            image_base,
            loader_flags,
            magic,
            major_image_version,
            major_linker_version,
            major_operating_system_version,
            major_subsystem_version,
            minor_image_version,
            minor_linker_version,
            minor_operating_system_version,
            minor_subsystem_version,
            number_of_rva_and_sizes,
            section_alignment,
            size_of_code,
            size_of_headers,
            size_of_heap_commit,
            size_of_heap_reserve,
            size_of_image,
            size_of_initialized_data,
            size_of_stack_commit,
            size_of_stack_reserve,
            size_of_uninitialized_data,
            subsystem,
            win32_version_value,
        })
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
