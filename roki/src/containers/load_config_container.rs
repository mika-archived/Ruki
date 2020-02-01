use crate::constant::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG;
use crate::directories::LoadConfigDirectory;
use crate::Executable;

#[derive(Debug)]
pub struct LoadConfigContainer {
    directory: LoadConfigDirectory,
}

impl LoadConfigContainer {
    pub fn parse(executable: &Executable) -> Result<Option<Self>, failure::Error> {
        let data_directory = executable.optional_header().unwrap().data_directories()[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG as usize];
        let cfg_dir_size = data_directory.size();

        if cfg_dir_size == 0 {
            return Ok(None);
        }

        let section = match executable.in_section(data_directory) {
            Some(section) => section,
            None => {
                let msg = "Failed to read load config directory";
                return Err(failure::err_msg(msg));
            }
        };

        let offset = executable.rva_to_file_pointer(data_directory.virtual_address(), section);
        let directory = LoadConfigDirectory::parse(executable, offset)?;

        Ok(Some(LoadConfigContainer { directory }))
    }

    pub fn directory(&self) -> &LoadConfigDirectory {
        &self.directory
    }
}
