use std::fmt::{Display, Formatter};

use scroll::{ctx, Endian, Pread, BE, LE};

#[repr(C)]
#[derive(Debug, Default)]
pub struct GUID {
    data1: u32, // LE
    data2: u16, // LE
    data3: u16, // LE
    data4: u16, // BE
    data5: u32, // BE
    data6: u16, // BE
}

impl<'a> ctx::TryFromCtx<'a, Endian> for GUID {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], _endian: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let data1 = src.gread_with::<u32>(offset, LE)?;
        let data2 = src.gread_with::<u16>(offset, LE)?;
        let data3 = src.gread_with::<u16>(offset, LE)?;
        let data4 = src.gread_with::<u16>(offset, BE)?;
        let data5 = src.gread_with::<u32>(offset, BE)?;
        let data6 = src.gread_with::<u16>(offset, BE)?;

        Ok((GUID { data1, data2, data3, data4, data5, data6 }, *offset))
    }
}

impl Display for GUID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:X}-{:X}-{:X}-{:X}-{:X}{:X}", self.data1, self.data2, self.data3, self.data4, self.data5, self.data6)
    }
}
