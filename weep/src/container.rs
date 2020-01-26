use std::convert::TryInto;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use scroll::{Pread, LE};

mod data_directory;
mod dos_header;
mod file_header;
mod optional_header;

use dos_header::DosHeader;
use file_header::FileHeader;
use optional_header::OptionalHeader;

#[derive(Debug)]
pub struct SectionHeader {
    characteristics: u32,
    name: [char; 8], // return as string
    number_of_linenumbers: u16,
    number_of_relocations: u16,
    pointer_to_linenumbers: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    size_of_raw_data: u32,
    virtual_address: u32,
    virtual_size: u32,
}

impl SectionHeader {
    pub fn characteristics(&self) -> u32 {
        self.characteristics
    }

    pub fn name(&self) -> String {
        self.name.iter().cloned().collect::<String>()
    }

    pub fn number_of_linenumbers(&self) -> u16 {
        self.number_of_linenumbers
    }

    pub fn number_of_relocations(&self) -> u16 {
        self.number_of_relocations
    }

    pub fn pointer_to_linenumbers(&self) -> u32 {
        self.pointer_to_linenumbers
    }

    pub fn pointer_to_raw_data(&self) -> u32 {
        self.pointer_to_raw_data
    }

    pub fn pointer_to_relocations(&self) -> u32 {
        self.pointer_to_relocations
    }

    pub fn size_of_raw_data(&self) -> u32 {
        self.size_of_raw_data
    }

    pub fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    pub fn virtual_size(&self) -> u32 {
        self.virtual_size
    }
}

#[derive(Debug)]
pub struct DebugDirectory {
    address_of_raw_data: u32,
    characteristics: u32,
    major_version: u16,
    minor_version: u16,
    pointer_to_raw_data: u32,
    size_of_data: u32,
    time_date_stamps: u32,
    r#type: u32,
}

impl DebugDirectory {
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

    pub fn time_date_stamps(&self) -> u32 {
        self.time_date_stamps
    }

    pub fn r#type(&self) -> u32 {
        self.r#type
    }
}

#[derive(Debug)]
pub struct Container {
    path: String,
    buffer: Vec<u8>,
    reader: BufReader<File>,

    dos_header: Option<DosHeader>,
    file_header: Option<FileHeader>,
    optional_header: Option<OptionalHeader>,
    section_headers: Option<Vec<SectionHeader>>,

    export_data: Option<()>,
    import_data: Option<()>,
    resource_data: Option<()>,
    exception_data: Option<()>,
    security_data: Option<()>,
    base_relocation_data: Option<()>,
    debug_data: Option<Vec<DebugDirectory>>,
    architecture_data: Option<()>,
    global_pointer_data: Option<()>,
    tls_data: Option<()>,
    load_config_data: Option<()>,
    bound_import_data: Option<()>,
    entry_iat_data: Option<()>,
    delay_import_data: Option<()>,
    com_descriptor_data: Option<()>,
    // reserved: Option<()>,
}

impl Container {
    pub fn create(path: &Path) -> Result<Container, failure::Error> {
        let mut executable = match File::open(path) {
            Ok(executable) => executable,
            Err(e) => {
                let msg = format!("Error occurred while opening file: {}", e);
                return Err(failure::err_msg(msg));
            }
        };
        let mut buffer = Vec::new();
        executable.read_to_end(&mut buffer)?;
        executable.seek(SeekFrom::Start(0))?;

        let reader = BufReader::new(executable);

        Ok(Container {
            path: path.to_str().unwrap().to_owned(),
            buffer,
            reader,

            // headers
            dos_header: None,
            file_header: None,
            optional_header: None,
            section_headers: None,

            // data
            export_data: None,
            import_data: None,
            resource_data: None,
            exception_data: None,
            security_data: None,
            base_relocation_data: None,
            debug_data: None,
            architecture_data: None,
            global_pointer_data: None,
            tls_data: None,
            load_config_data: None,
            bound_import_data: None,
            entry_iat_data: None,
            delay_import_data: None,
            com_descriptor_data: None,
        })
    }

    // getters
    pub fn buffer(&self) -> &[u8] {
        let array: &[u8] = self.buffer[..].try_into().unwrap();
        return array;
    }

    pub fn dos_header(&self) -> Option<&DosHeader> {
        self.dos_header.as_ref()
    }

    pub fn file_header(&self) -> Option<&FileHeader> {
        self.file_header.as_ref()
    }

    pub fn optional_header(&self) -> Option<&OptionalHeader> {
        self.optional_header.as_ref()
    }

    pub fn section_headers(&self) -> Option<Vec<&SectionHeader>> {
        match &self.section_headers {
            Some(section_headers) => Some(section_headers.iter().map(|s| s).collect()),
            None => None,
        }
    }

    pub fn debug_data(&self) -> Option<Vec<&DebugDirectory>> {
        match &self.debug_data {
            Some(debug_data) => Some(debug_data.iter().map(|s| s).collect()),
            None => None,
        }
    }

    // functions
    pub fn parse(&mut self) -> Result<(), failure::Error> {
        // headers
        self.dos_header = Some(DosHeader::parse(self)?);
        if !self.dos_header().unwrap().is_windows_executable() {
            return Ok(());
        }

        let mut offset: usize = 0;

        self.file_header = Some(FileHeader::parse(self, &mut offset)?);
        if !self.file_header().unwrap().is_portable_executable() {
            return Ok(());
        }

        self.optional_header = Some(OptionalHeader::parse(self, &mut offset)?);

        // self.section_headers = Some(self.parse_section_header()?);

        // directories
        // TODO other data
        // self.debug_data = Some(self.parse_debug_data()?);

        Ok(())
    }

    /*
    fn parse_section_header(&mut self) -> Result<Vec<SectionHeader>, failure::Error> {
        let mut vector: Vec<SectionHeader> = Vec::new();

        for _ in 0..self.nt_container().unwrap().number_of_sections {
            let name = self.read_bytes(8)?.into_iter().map(|s| s as char).collect::<Vec<char>>();
            let virtual_size = self.read_as_u32()?;
            let virtual_address = self.read_as_u32()?;
            let size_of_raw_data = self.read_as_u32()?;
            let pointer_to_raw_data = self.read_as_u32()?;
            let pointer_to_relocations = self.read_as_u32()?;
            let pointer_to_linenumbers = self.read_as_u32()?;
            let number_of_relocations = self.read_as_u16()?;
            let number_of_linenumbers = self.read_as_u16()?;
            let characteristics = self.read_as_u32()?;

            vector.push(SectionHeader {
                name: name[0..8].try_into().unwrap(),
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                pointer_to_relocations,
                pointer_to_linenumbers,
                number_of_relocations,
                number_of_linenumbers,
                characteristics,
            });
        }

        Ok(vector)
    }

    fn parse_debug_data(&mut self) -> Result<Vec<DebugDirectory>, failure::Error> {
        let directory = self.nt_container().unwrap().data_directories()[6];
        let debug_info_size = directory.size();
        if debug_info_size == 0 {
            return Ok(vec![]); // empty directory
        }

        let section = match self.in_section(directory) {
            Some(section) => section,
            None => {
                let msg = "Error: failed to load directory data";
                return Err(failure::err_msg(msg));
            }
        };

        // RVA to file pointer
        let address = directory.virtual_address() - section.virtual_address() + section.pointer_to_raw_data();
        self.seek_to(SeekFrom::Start(address as u64))?;

        let mut vector: Vec<DebugDirectory> = Vec::new();
        // debug tables are 28 bytes
        for _ in 0..(debug_info_size / 28) {
            let characteristics = self.read_as_u32()?;
            let time_date_stamps = self.read_as_u32()?;
            let major_version = self.read_as_u16()?;
            let minor_version = self.read_as_u16()?;
            let r#type = self.read_as_u32()?;
            let size_of_data = self.read_as_u32()?;
            let address_of_raw_data = self.read_as_u32()?;
            let pointer_to_raw_data = self.read_as_u32()?;

            vector.push(DebugDirectory {
                address_of_raw_data,
                characteristics,
                major_version,
                minor_version,
                pointer_to_raw_data,
                size_of_data,
                time_date_stamps,
                r#type,
            });
        }

        Ok(vector)
    }
    */

    /*
    pub(in crate::container) fn in_section(&self, directory: &DirectoryEntry) -> Option<&SectionHeader> {
        let nt_container = self.nt_container().unwrap().number_of_sections();
        let address = directory.virtual_address();

        for i in 0..nt_container {
            let section = self.section_headers().unwrap()[i as usize];
            #[rustfmt::skip]
            let size = if section.virtual_size() == 0 { section.size_of_raw_data() } else { section.virtual_size() };

            if section.virtual_address() <= address && address < section.virtual_address() + size {
                return Some(section);
            }
        }

        None
    }
    */

    // reader functions
    pub(in crate::container) fn read_bytes(&mut self, size: u8) -> Result<Vec<u8>, failure::Error> {
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

    // UNSIGNED CHAR, BYTE, u8
    pub(in crate::container) fn read_as_u8(&mut self) -> Result<u8, failure::Error> {
        let bytes = self.read_bytes(1)?;
        return Ok(u8::from_le_bytes(bytes[0..1].try_into().unwrap()));
    }

    // UNSIGNED SHORT, WORD, u16
    pub(in crate::container) fn read_as_u16(&mut self) -> Result<u16, failure::Error> {
        let bytes = self.read_bytes(2)?;
        return Ok(u16::from_le_bytes(bytes[0..2].try_into().unwrap()));
    }

    // UNSIGNED INT, DOUBLE WORD, u32
    pub(in crate::container) fn read_as_u32(&mut self) -> Result<u32, failure::Error> {
        let bytes = self.read_bytes(4)?;
        return Ok(u32::from_le_bytes(bytes[0..4].try_into().unwrap()));
    }

    // UNSIGNED LONG LONG, u64
    pub(in crate::container) fn read_as_u64(&mut self) -> Result<u64, failure::Error> {
        let bytes = self.read_bytes(8)?;
        return Ok(u64::from_le_bytes(bytes[0..8].try_into().unwrap()));
    }

    pub(in crate::container) fn seek_to(&mut self, seek: SeekFrom) -> Result<(), failure::Error> {
        match self.reader.seek(seek) {
            Ok(_) => return Ok(()),
            Err(_) => {
                let msg = format!("Error occurred while seeking to specified address");
                return Err(failure::err_msg(msg));
            }
        }
    }
}
