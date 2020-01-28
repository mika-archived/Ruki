use scroll::Pread;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pread)]
pub struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

impl DataDirectory {
    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn virtual_address(&self) -> u32 {
        self.virtual_address
    }
}
