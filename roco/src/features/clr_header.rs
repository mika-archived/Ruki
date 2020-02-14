use roki::Executable;

pub fn print(executable: &Executable) -> () {
  let clr_container = match executable.com_descriptor_data() {
    Some(com_descriptor_data) => com_descriptor_data,
    None => return,
  };

  println!("\nCOM DESCRIPTOR (CLR) HEADER VALUES");

  let clr_header = clr_container.cor20_header();

  fn add_if_includes(flags: u32, flag: u32, vector: &mut Vec<String>, text: &str) -> () {
    if flags & flag == flag {
      vector.push(text.to_owned());
    }
  }

  let mut flags: Vec<String> = Vec::new();
  add_if_includes(clr_header.flags(), 0x00000001, &mut flags, "COMIMAGE_FLAGS_ILONLY");
  add_if_includes(clr_header.flags(), 0x00000002, &mut flags, "COMIMAGE_FLAGS_32BITREQUIRED");
  add_if_includes(clr_header.flags(), 0x00000008, &mut flags, "COMIMAGE_FLAGS_STRONGNAMESIGNED");
  add_if_includes(clr_header.flags(), 0x00000010, &mut flags, "COMIMAGE_FLAGS_NATIVE_ENTRYPOINT");
  add_if_includes(clr_header.flags(), 0x00010000, &mut flags, "COMIMAGE_FLAGS_TRACKDEBUGDATA");

  println!(
    "    cb                                  : {:#010X}
    runtime version                     : {}.{}
    metadata rva/size                   : {:#010X} / {:#010X}
    flags                               : {:#010X}\
  ",
    clr_header.cb(),
    clr_header.major_runtime_version(),
    clr_header.minor_runtime_version(),
    clr_header.meta_data().virtual_address(),
    clr_header.meta_data().size(),
    clr_header.flags()
  );

  for flag in flags {
    println!("        {}", flag);
  }

  println!(
    "    entry point rva                     : {:#010X}
    resources rva/size                  : {:#010X} / {:#010X}
    strong name signature rva/size      : {:#010X} / {:#010X}
    code manager table rva/size         : {:#010X} / {:#010X}
    v table fixups rva/size             : {:#010X} / {:#010X}
    export address table jumps rva/size : {:#010X} / {:#010X}
    managed native header rva/size      : {:#010X} / {:#010X}
    ",
    clr_header.entry_point_rva(),
    clr_header.resources().virtual_address(),
    clr_header.resources().size(),
    clr_header.strong_name_signature().virtual_address(),
    clr_header.strong_name_signature().size(),
    clr_header.code_manager_table().virtual_address(),
    clr_header.code_manager_table().size(),
    clr_header.v_table_fixups().virtual_address(),
    clr_header.v_table_fixups().size(),
    clr_header.export_address_table_jumps().virtual_address(),
    clr_header.export_address_table_jumps().size(),
    clr_header.managed_native_header().virtual_address(),
    clr_header.managed_native_header().size()
  );
}
