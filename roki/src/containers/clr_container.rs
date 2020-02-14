use crate::headers::Cor20Header;
use crate::Executable;

#[derive(Debug)]
pub struct ClrContainer {
  cor20_header: Cor20Header,
}

impl ClrContainer {
  pub fn parse(executable: &Executable) -> Result<Option<Self>, failure::Error> {
    let cor20_header = match Cor20Header::parse(executable)? {
      Some(header) => header,
      None => return Ok(None),
    };

    Ok(Some(ClrContainer { cor20_header }))
  }

  pub fn cor20_header(&self) -> &Cor20Header {
    &self.cor20_header
  }
}
