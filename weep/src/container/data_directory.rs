#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

impl DataDirectory {
    pub fn new(virtual_address: u32, size: u32) -> Self {
        DataDirectory { virtual_address, size }
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn virtual_address(&self) -> u32 {
        self.virtual_address
    }
}
