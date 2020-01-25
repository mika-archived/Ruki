use std::convert::TryInto;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug)]
pub struct DosContainer {
    addr_of_nt_header: i32,
    is_windows_executable: bool,
}

#[allow(dead_code)]
impl DosContainer {
    pub fn is_windows_executable(&self) -> bool {
        self.is_windows_executable
    }
}

#[derive(Debug)]
pub struct DirectoryEntries {
    size: u32,
    virtual_address: u32,
}

#[allow(dead_code)]
impl DirectoryEntries {
    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn virtual_address(&self) -> u32 {
        self.virtual_address
    }
}

#[derive(Debug)]
pub struct NtContainer {
    // see: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header

    // Signature
    is_portable_executable: bool,

    // File Header
    characteristics: u16,
    machine_raw: u16,
    number_of_sections: u16,
    number_of_symbols: u32,
    pointer_to_symbol_table: u32,
    size_of_optional_header: u16,
    time_date_stamps: u32,

    // Optional Header
    address_of_entry_point: u32,
    arch_raw: u16, // aka magic
    base_of_code: u32,
    base_of_data: u32,
    checksum: u32,
    data_dictionary: [DirectoryEntries; 16],
    dll_characteristics: u16,
    file_alignment: u32,
    image_base: u32,
    loader_flags: u32,
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
    size_of_heap_commit: u32,
    size_of_heap_reserve: u32,
    size_of_image: u32,
    size_of_initialized_data: u32,
    size_of_stack_commit: u32,
    size_of_stack_reserve: u32,
    size_of_uninitialized_data: u32,
    subsystem: u16,
    win32_version_value: u32,
}

#[allow(dead_code)]
impl NtContainer {
    pub fn address_of_entry_point(&self) -> String {
        format!("0x{:X}", self.address_of_entry_point)
    }

    pub fn arch(&self) -> Result<&'static str, ()> {
        match self.arch_raw {
            0x010b => Ok("PE32"),
            0x020b => Ok("PE32+"),
            _ => Err(()),
        }
    }

    pub fn base_of_code(&self) -> String {
        format!("0x{:X}", self.base_of_code)
    }

    pub fn base_of_data(&self) -> String {
        format!("0x{:X}", self.base_of_data)
    }

    pub fn characteristics(&self) -> String {
        format!("0x{:X}", self.characteristics)
    }

    pub fn checksum(&self) -> u32 {
        self.checksum
    }

    pub fn data_dictionary(&self) -> &[DirectoryEntries; 16] {
        &self.data_dictionary
    }

    pub fn dll_characteristics(&self) -> String {
        format!("0x{:X}", self.dll_characteristics)
    }

    pub fn file_alignment(&self) -> String {
        format!("0x{:X}", self.file_alignment)
    }

    pub fn image_base(&self) -> String {
        format!("0x{:X}", self.image_base)
    }

    pub fn image_version(&self) -> String {
        format!("{}.{}", self.major_image_version, self.minor_image_version)
    }

    pub fn is_portable_executable(&self) -> bool {
        self.is_portable_executable
    }

    pub fn linker_version(&self) -> String {
        format!("{}.{}", self.major_linker_version, self.minor_linker_version)
    }

    pub fn loader_flags(&self) -> u32 {
        self.loader_flags
    }

    pub fn machine(&self) -> Result<&'static str, ()> {
        match self.machine_raw {
            0x014C => Ok("x86"),
            0x0200 => Ok("Intel Itanium"),
            0x8664 => Ok("x64"),
            _ => Err(()),
        }
    }

    pub fn number_of_rva_and_sizes(&self) -> u32 {
        self.number_of_rva_and_sizes
    }

    pub fn number_of_sections(&self) -> u16 {
        self.number_of_sections
    }

    pub fn number_of_symbols(&self) -> u32 {
        self.number_of_symbols // always 0
    }

    pub fn operating_system_version(&self) -> String {
        format!("{}.{}", self.major_operating_system_version, self.minor_operating_system_version)
    }

    pub fn pointer_to_symbol_table(&self) -> u32 {
        self.pointer_to_symbol_table // always 0
    }

    pub fn section_alignment(&self) -> String {
        format!("0x{:X}", self.section_alignment)
    }

    pub fn size_of_code(&self) -> u32 {
        self.size_of_code
    }

    pub fn size_of_headers(&self) -> u32 {
        self.size_of_headers
    }

    pub fn size_of_heap_commit(&self) -> u32 {
        self.size_of_heap_commit
    }

    pub fn size_of_heap_reserve(&self) -> u32 {
        self.size_of_heap_reserve
    }

    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    pub fn size_of_initialized_data(&self) -> u32 {
        self.size_of_initialized_data
    }

    pub fn size_of_optional_header(&self) -> u16 {
        self.size_of_optional_header
    }

    pub fn size_of_stack_commit(&self) -> u32 {
        self.size_of_stack_commit
    }

    pub fn size_of_stack_reserve(&self) -> u32 {
        self.size_of_stack_reserve
    }

    pub fn size_of_uninitialized_data(&self) -> u32 {
        self.size_of_uninitialized_data
    }

    pub fn subsystem(&self) -> Result<&'static str, ()> {
        match self.subsystem {
            0 => Ok("Unknown"),
            1 => Ok("No subsystem required"),
            2 => Ok("Windows GUI"),
            3 => Ok("Windows CUI"),
            5 => Ok("OS/2 CUI"),
            7 => Ok("POSIX CUI"),
            9 => Ok("Windows CE"),
            10 => Ok("EFI application"),
            11 => Ok("EFI driver with boot services"),
            12 => Ok("EFI driver with runtime services"),
            13 => Ok("EFI ROM"),
            14 => Ok("XBox"),
            16 => Ok("Boot application"),
            _ => Err(()),
        }
    }

    pub fn time_date_stamps(&self) -> String {
        format!("0x{:X}", self.time_date_stamps)
    }
}

#[derive(Debug)]
pub struct Container {
    reader: BufReader<File>,

    dos_container: Option<DosContainer>,
    nt_container: Option<NtContainer>,
}

impl Container {
    pub fn create(path: &Path) -> Result<Container, failure::Error> {
        let executable = match File::open(path) {
            Ok(executable) => executable,
            Err(e) => {
                let msg = format!("Error occurred while opening file: {}", e);
                return Err(failure::err_msg(msg));
            }
        };
        let reader = BufReader::new(executable);

        Ok(Container {
            reader,

            // containers
            dos_container: None,
            nt_container: None,
        })
    }

    // getters
    pub fn dos_container(&mut self) -> Option<&DosContainer> {
        self.dos_container.as_ref()
    }

    pub fn nt_container(&mut self) -> Option<&NtContainer> {
        self.nt_container.as_ref()
    }

    // functions
    pub fn parse(&mut self) -> Result<(), failure::Error> {
        self.dos_container = Some(self.parse_dos_header()?);
        self.nt_container = Some(self.parse_nt_header()?);

        Ok(())
    }

    fn parse_dos_header(&mut self) -> Result<DosContainer, failure::Error> {
        let bytes = self.read_bytes(2)?;
        let is_windows_executable = bytes[0] == 0x4D && bytes[1] == 0x5A;

        self.seek_to(SeekFrom::Start(0x3C))?;

        let addr_of_nt_header = i32::from_le_bytes(self.read_long()?);

        Ok(DosContainer {
            addr_of_nt_header,
            is_windows_executable,
        })
    }

    fn parse_nt_header(&mut self) -> Result<NtContainer, failure::Error> {
        self.seek_to(SeekFrom::Start(self.dos_container.as_ref().unwrap().addr_of_nt_header as u64))?;

        // sig
        let bytes = self.read_bytes(4)?;
        let is_portable_executable = bytes[0] == 0x50 && bytes[1] == 0x45 && bytes[2] == 0x00 && bytes[3] == 0x00;

        // file header
        let machine_raw = u16::from_le_bytes(self.read_word()?);
        let number_of_sections = u16::from_le_bytes(self.read_word()?);
        let time_date_stamps = u32::from_le_bytes(self.read_long()?);
        let pointer_to_symbol_table = u32::from_le_bytes(self.read_long()?);
        let number_of_symbols = u32::from_le_bytes(self.read_long()?);
        let size_of_optional_header = u16::from_le_bytes(self.read_word()?);
        let characteristics = u16::from_le_bytes(self.read_word()?);

        // optional header
        let arch_raw = u16::from_le_bytes(self.read_word()?);
        let major_linker_version = u8::from_le_bytes(self.read_byte()?);
        let minor_linker_version = u8::from_le_bytes(self.read_byte()?);
        let size_of_code = u32::from_le_bytes(self.read_long()?);
        let size_of_initialized_data = u32::from_le_bytes(self.read_long()?);
        let size_of_uninitialized_data = u32::from_le_bytes(self.read_long()?);
        let address_of_entry_point = u32::from_le_bytes(self.read_long()?);
        let base_of_code = u32::from_le_bytes(self.read_long()?);
        let base_of_data = u32::from_le_bytes(self.read_long()?);
        let image_base = u32::from_le_bytes(self.read_long()?);
        let section_alignment = u32::from_le_bytes(self.read_long()?);
        let file_alignment = u32::from_le_bytes(self.read_long()?);
        let major_operating_system_version = u16::from_le_bytes(self.read_word()?);
        let minor_operating_system_version = u16::from_le_bytes(self.read_word()?);
        let major_image_version = u16::from_le_bytes(self.read_word()?);
        let minor_image_version = u16::from_le_bytes(self.read_word()?);
        let major_subsystem_version = u16::from_le_bytes(self.read_word()?);
        let minor_subsystem_version = u16::from_le_bytes(self.read_word()?);
        let win32_version_value = u32::from_le_bytes(self.read_long()?);
        let size_of_image = u32::from_le_bytes(self.read_long()?);
        let size_of_headers = u32::from_le_bytes(self.read_long()?);
        let checksum = u32::from_le_bytes(self.read_long()?);
        let subsystem = u16::from_le_bytes(self.read_word()?);
        let dll_characteristics = u16::from_le_bytes(self.read_word()?);
        let size_of_stack_reserve = u32::from_le_bytes(self.read_long()?);
        let size_of_stack_commit = u32::from_le_bytes(self.read_long()?);
        let size_of_heap_reserve = u32::from_le_bytes(self.read_long()?);
        let size_of_heap_commit = u32::from_le_bytes(self.read_long()?);
        let loader_flags = u32::from_le_bytes(self.read_long()?);
        let number_of_rva_and_sizes = u32::from_le_bytes(self.read_long()?);

        fn create_directory_entry(container: &mut Container) -> Result<DirectoryEntries, failure::Error> {
            Ok(DirectoryEntries {
                virtual_address: u32::from_le_bytes(container.read_long()?),
                size: u32::from_le_bytes(container.read_long()?),
            })
        }

        // directory entries
        let export = create_directory_entry(self)?;
        let import = create_directory_entry(self)?;
        let resource = create_directory_entry(self)?;
        let exception = create_directory_entry(self)?;
        let security = create_directory_entry(self)?;
        let basereloc = create_directory_entry(self)?;
        let debug = create_directory_entry(self)?;
        let architecture = create_directory_entry(self)?;
        let global_ptr = create_directory_entry(self)?;
        let tls = create_directory_entry(self)?;
        let load_config = create_directory_entry(self)?;
        let bound_import = create_directory_entry(self)?;
        let entry_iat = create_directory_entry(self)?;
        let delay_import = create_directory_entry(self)?;
        let com_descriptor = create_directory_entry(self)?;
        let reserved = create_directory_entry(self)?;

        Ok(NtContainer {
            address_of_entry_point,
            arch_raw,
            base_of_code,
            base_of_data,
            characteristics,
            data_dictionary: [
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
            is_portable_executable,
            loader_flags,
            machine_raw,
            major_image_version,
            major_linker_version,
            major_operating_system_version,
            major_subsystem_version,
            minor_image_version,
            minor_linker_version,
            minor_operating_system_version,
            minor_subsystem_version,
            number_of_rva_and_sizes,
            number_of_sections,
            number_of_symbols,
            pointer_to_symbol_table,
            section_alignment,
            size_of_code,
            size_of_headers,
            size_of_heap_commit,
            size_of_heap_reserve,
            size_of_image,
            size_of_initialized_data,
            size_of_optional_header,
            size_of_stack_commit,
            size_of_stack_reserve,
            size_of_uninitialized_data,
            subsystem,
            time_date_stamps,
            win32_version_value,
        })
    }

    fn read_bytes(&mut self, size: u8) -> Result<Vec<u8>, failure::Error> {
        let mut buffer = [0; 1];
        let mut vector: Vec<u8> = Vec::new();

        for _ in 0..size {
            match &self.reader.read(&mut buffer).unwrap_or(0) {
                0 => {
                    let msg = format!("Failed to read {} bytes from stream", size);
                    return Err(failure::err_msg(msg));
                }
                _ => vector.push(buffer[0]),
            };
        }

        Ok(vector)
    }

    fn read_byte(&mut self) -> Result<[u8; 1], failure::Error> {
        let bytes = self.read_bytes(1)?;
        return Ok(bytes[0..1].try_into().unwrap());
    }

    fn read_word(&mut self) -> Result<[u8; 2], failure::Error> {
        let bytes = self.read_bytes(2)?;
        return Ok(bytes[0..2].try_into().unwrap());
    }

    fn read_long(&mut self) -> Result<[u8; 4], failure::Error> {
        let bytes = self.read_bytes(4)?;
        return Ok(bytes[0..4].try_into().unwrap());
    }

    fn seek_to(&mut self, seek: SeekFrom) -> Result<(), failure::Error> {
        match self.reader.seek(seek) {
            Ok(_) => return Ok(()),
            Err(_) => {
                #[rustfmt::skip]
                let msg = format!("Error occurred while seeking to specified address");
                return Err(failure::err_msg(msg));
            }
        }
    }
}
