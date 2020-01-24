use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug)]
pub struct DosContainer {
    addr_of_nt_header: i32,
    is_windows_executable: bool,
}

#[derive(Debug)]
pub struct Container {
    reader: BufReader<File>,

    dos_container: Option<DosContainer>,
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
        })
    }

    // getters
    pub fn is_windows_executable(&mut self) -> bool {
        let dos_container = self.dos_container.as_ref().unwrap();
        return dos_container.is_windows_executable;
    }

    // functions
    pub fn parse(&mut self) -> Result<(), failure::Error> {
        self.dos_container = Some(self.parse_dos_header()?);

        Ok(())
    }

    fn parse_dos_header(&mut self) -> Result<DosContainer, failure::Error> {
        let bytes = self.read_bytes(2)?;
        let is_windows_executable = bytes[0] == 0x4D && bytes[1] == 0x5A;

        self.seek_to(SeekFrom::Start(0x3C))?;

        let bytes = self.read_bytes(4)?;
        let addr_of_nt_header = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        Ok(DosContainer {
            addr_of_nt_header,
            is_windows_executable,
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
