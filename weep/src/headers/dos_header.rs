use scroll::{Pread, LE};

use crate::Executable;

#[derive(Debug)]
pub struct DosHeader {
    addr_of_nt_header: i32,
    is_windows_executable: bool,
}

impl DosHeader {
    pub fn parse(executable: &mut Executable) -> Result<DosHeader, failure::Error> {
        let signature = executable.buffer().pread_with::<u16>(0, LE).map_err(|_| {
            let msg = format!("Could not parse DOS signature at {:#X}", 0);
            return failure::err_msg(msg);
        })?;
        let is_windows_executable = signature == 0x5A4D;
        if !is_windows_executable {
            return Ok(DosHeader {
                addr_of_nt_header: 0,
                is_windows_executable: false,
            });
        }

        let addr_of_nt_header = executable.buffer().pread_with::<i32>(0x3C, LE).map_err(|_| {
            let msg = format!("Could not parse PE header pointer at {:#X}", 0x3C);
            return failure::err_msg(msg);
        })?;

        Ok(DosHeader { addr_of_nt_header, is_windows_executable })
    }

    // getters
    pub fn addr_of_nt_header(&self) -> i32 {
        self.addr_of_nt_header
    }

    pub fn is_windows_executable(&self) -> bool {
        self.is_windows_executable
    }
}
