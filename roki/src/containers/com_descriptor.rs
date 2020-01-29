use crate::constant::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;
use crate::headers::Cor20Header;
use crate::Executable;

#[derive(Debug)]
pub struct ComDescriptor {
    cor20_header: Cor20Header,
}

impl ComDescriptor {
    pub fn parse(executable: &Executable) -> Result<Option<Self>, failure::Error> {
        let data_directory = executable.optional_header().unwrap().data_directories()[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR as usize];
        if data_directory.size() == 0 {
            return Ok(None);
        }

        let cor20_header = Cor20Header::parse(executable)?;
        let descriptor = match cor20_header {
            Some(header) => Some(ComDescriptor::parse_clr_data(header, executable)?),
            None => None,
        };

        Ok(descriptor)
    }

    fn parse_clr_data(header: Cor20Header, executable: &Executable) -> Result<Self, failure::Error> {
        Ok(ComDescriptor { cor20_header: header })
    }
}
