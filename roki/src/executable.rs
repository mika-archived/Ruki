use std::convert::TryInto;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::containers::{ComDescriptor, DebugContainer, ExportContainer, ImportContainer, LoadConfigContainer};
use crate::directories::DataDirectory;
use crate::headers::{DosHeader, FileHeader, OptionalHeader, SectionHeader};

const X64_MACHINE: u16 = 0x8664;

#[derive(Debug)]
pub struct Executable {
    path: String,
    buffer: Vec<u8>,

    dos_header: Option<DosHeader>,
    file_header: Option<FileHeader>,
    optional_header: Option<OptionalHeader>,
    section_headers: Option<Vec<SectionHeader>>,

    export_data: Option<ExportContainer>,
    import_data: Option<ImportContainer>,
    resource_data: Option<()>,
    exception_data: Option<()>,
    security_data: Option<()>,
    base_relocation_data: Option<()>,
    debug_data: Option<Vec<DebugContainer>>,
    architecture_data: Option<()>,
    global_pointer_data: Option<()>,
    tls_data: Option<()>,
    load_config_data: Option<LoadConfigContainer>,
    bound_import_data: Option<()>,
    entry_iat_data: Option<()>,
    delay_import_data: Option<()>,
    com_descriptor_data: Option<ComDescriptor>,
    // reserved: Option<()>,
}

impl Executable {
    pub fn new(path: &Path) -> Result<Self, failure::Error> {
        let mut executable = match File::open(path) {
            Ok(executable) => executable,
            Err(e) => {
                let msg = format!("Error occurred while opening file: {}", e);
                return Err(failure::err_msg(msg));
            }
        };
        let mut buffer = Vec::new();
        executable.read_to_end(&mut buffer)?;

        Ok(Executable {
            path: path.to_str().unwrap().to_owned(),
            buffer,

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

    pub fn com_descriptor_data(&self) -> Option<&ComDescriptor> {
        self.com_descriptor_data.as_ref()
    }

    pub fn debug_data(&self) -> Option<Vec<&DebugContainer>> {
        match &self.debug_data {
            Some(debug_data) => Some(debug_data.iter().map(|s| s).collect()),
            None => None,
        }
    }

    pub fn dos_header(&self) -> Option<&DosHeader> {
        self.dos_header.as_ref()
    }

    pub fn export_data(&self) -> Option<&ExportContainer> {
        self.export_data.as_ref()
    }

    pub fn file_header(&self) -> Option<&FileHeader> {
        self.file_header.as_ref()
    }

    pub fn import_data(&self) -> Option<&ImportContainer> {
        self.import_data.as_ref()
    }

    pub fn load_config_data(&self) -> Option<&LoadConfigContainer> {
        self.load_config_data.as_ref()
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

        let mut section_headers: Vec<SectionHeader> = Vec::new();
        for _ in 0..self.file_header().unwrap().number_of_sections() {
            section_headers.push(SectionHeader::parse(self, &mut offset)?);
        }

        self.section_headers = Some(section_headers);

        // directories
        // TODO other data
        self.export_data = ExportContainer::parse(self)?;
        self.import_data = ImportContainer::parse(self)?;
        self.debug_data = DebugContainer::parse(self)?;
        self.load_config_data = LoadConfigContainer::parse(self)?;
        self.com_descriptor_data = ComDescriptor::parse(self)?;

        Ok(())
    }

    pub(in crate) fn in_section(&self, directory: &DataDirectory) -> Option<&SectionHeader> {
        let number_of_sections = self.file_header().unwrap().number_of_sections();
        let address = directory.virtual_address();

        for i in 0..number_of_sections {
            let section = self.section_headers().unwrap()[i as usize];
            #[rustfmt::skip]
            let size = if section.virtual_size() == 0 { section.size_of_raw_data() } else { section.virtual_size() };

            if section.virtual_address() <= address && address < section.virtual_address() + size {
                return Some(section);
            }
        }

        None
    }

    pub(in crate) fn rva_to_file_pointer(&self, rva: u32, section: &SectionHeader) -> usize {
        (rva - section.virtual_address() + section.pointer_to_raw_data()).try_into().unwrap()
    }

    pub(in crate) fn is_x64(&self) -> bool {
        self.file_header().unwrap().machine() == X64_MACHINE
    }
}
