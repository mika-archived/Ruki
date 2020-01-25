use std::env;
use std::path::Path;

use exitfailure::ExitFailure;
use windows_executable_parser::Container;

fn main() -> Result<(), ExitFailure> {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        1 => usage(),
        2 => parse(&args.get(1).unwrap())?,
        _ => {}
    };

    Ok(())
}

fn usage() {
    print!(
        "\
WinParse - Parsing Windows Portable Executable File and dump it

USAGE:
    win-parse [Windows Executable]"
    );
}

fn parse(path: &str) -> Result<(), failure::Error> {
    let path = Path::new(path);

    // check file existence
    if !path.exists() || !path.is_file() {
        let msg = format!("Path `{}` is no such file or executable file", path.display());
        return Err(failure::err_msg(msg));
    }

    // create EXE container
    let mut container = Container::create(path)?;
    container.parse()?;

    println!("Dump of file {}\n", path.file_name().unwrap().to_str().unwrap());

    if container.dos_container().unwrap().is_windows_executable() {
        println!("DOS signature found");
    }

    if container.nt_container().unwrap().is_portable_executable() {
        println!("PE signature found");
    }

    print_file_headers(&container);
    print_optional_headers(&container);
    print_section_headers(&container);

    Ok(())
}

fn print_file_headers(container: &Container) -> () {
    let nt_container = container.nt_container().unwrap();

    let machine = match nt_container.machine() {
        0x014C => "x86",
        0x0200 => "Intel IPF",
        0x8664 => "x64",
        _ => "Unknown",
    };

    fn add_if_includes(characteristics: u16, flag: u16, vector: &mut Vec<String>, text: &str) -> () {
        if characteristics & flag == flag {
            vector.push(text.to_owned());
        }
    }

    let mut characteristics: Vec<String> = Vec::new();
    add_if_includes(nt_container.characteristics(), 0x0001, &mut characteristics, "IMAGE_FILE_RELOCS_STRIPPED");
    add_if_includes(nt_container.characteristics(), 0x0002, &mut characteristics, "IMAGE_FILE_EXECUTABLE_IMAGE");
    add_if_includes(nt_container.characteristics(), 0x0004, &mut characteristics, "IMAGE_FILE_LINE_NUMS_STRIPPED");
    add_if_includes(nt_container.characteristics(), 0x0008, &mut characteristics, "IMAGE_FILE_LOCAL_SYMS_STRIPPED");
    add_if_includes(nt_container.characteristics(), 0x0010, &mut characteristics, "IMAGE_FILE_AGGRESIVE_WS_TRIM");
    add_if_includes(nt_container.characteristics(), 0x0020, &mut characteristics, "IMAGE_FILE_LARGE_ADDRESS_AWARE");
    add_if_includes(nt_container.characteristics(), 0x0080, &mut characteristics, "IMAGE_FILE_BYTES_REVERSED_LO");
    add_if_includes(nt_container.characteristics(), 0x0100, &mut characteristics, "IMAGE_FILE_32BIT_MACHINE");
    add_if_includes(nt_container.characteristics(), 0x0200, &mut characteristics, "IMAGE_FILE_DEBUG_STRIPPED");
    add_if_includes(nt_container.characteristics(), 0x0400, &mut characteristics, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP");
    add_if_includes(nt_container.characteristics(), 0x0800, &mut characteristics, "IMAGE_FILE_NET_RUN_FROM_SWAP");
    add_if_includes(nt_container.characteristics(), 0x1000, &mut characteristics, "IMAGE_FILE_SYSTEM");
    add_if_includes(nt_container.characteristics(), 0x2000, &mut characteristics, "IMAGE_FILE_DLL");
    add_if_includes(nt_container.characteristics(), 0x4000, &mut characteristics, "IMAGE_FILE_UP_SYSTEM_ONLY");
    add_if_includes(nt_container.characteristics(), 0x8000, &mut characteristics, "IMAGE_FILE_BYTES_REVERSED_HI");

    println!(
        "
FILE HEADER VALUES
    machine                      : {:X} ({})
    number of sections           : {:X}
    time date stamps             : {:X}
    file pointer to symbol table : {:X}
    number of symbols            : {:X}
    size of optional header      : {:X}
    characteristics              : {:X}\
    ",
        nt_container.machine(),
        machine,
        nt_container.number_of_sections(),
        nt_container.time_date_stamps(),
        nt_container.pointer_to_symbol_table(),
        nt_container.number_of_symbols(),
        nt_container.size_of_optional_header(),
        nt_container.characteristics(),
    );

    for characteristic in characteristics {
        println!("        {}", characteristic);
    }
}

fn print_optional_headers(container: &Container) -> () {
    let nt_container = container.nt_container().unwrap();

    let magic = match nt_container.arch() {
        0x10b => "PE32  (x86)",
        0x20b => "PE32+ (x64)",
        0x107 => "ROM",
        _ => "Unknown",
    };
    let subsystem = match nt_container.subsystem() {
        1 => "No subsystem required",
        2 => "Windows GUI",
        3 => "Windows CUI",
        5 => "OS/2 CUI",
        7 => "POSIX CUI",
        9 => "Windows CE",
        10 => "EFI application",
        11 => "EFI driver with boot",
        12 => "EFI driver with runtime",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Boot",
        _ => "Unknown",
    };

    fn add_if_includes(characteristics: u16, flag: u16, vector: &mut Vec<String>, text: &str) -> () {
        if characteristics & flag == flag {
            vector.push(text.to_owned());
        }
    }
    let mut characteristics: Vec<String> = Vec::new();
    add_if_includes(nt_container.dll_characteristics(), 0x0001, &mut characteristics, "RESERVED");
    add_if_includes(nt_container.dll_characteristics(), 0x0002, &mut characteristics, "RESERVED");
    add_if_includes(nt_container.dll_characteristics(), 0x0004, &mut characteristics, "RESERVED");
    add_if_includes(nt_container.dll_characteristics(), 0x0008, &mut characteristics, "RESERVED");
    add_if_includes(nt_container.dll_characteristics(), 0x0040, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE");
    add_if_includes(nt_container.dll_characteristics(), 0x0080, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY");
    add_if_includes(nt_container.dll_characteristics(), 0x0100, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT");
    add_if_includes(nt_container.dll_characteristics(), 0x0200, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION");
    add_if_includes(nt_container.dll_characteristics(), 0x0400, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_NO_SEH");
    add_if_includes(nt_container.dll_characteristics(), 0x0800, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_NO_BIND");
    add_if_includes(nt_container.dll_characteristics(), 0x1000, &mut characteristics, "RESERVED");
    add_if_includes(nt_container.dll_characteristics(), 0x2000, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER");
    add_if_includes(nt_container.dll_characteristics(), 0x4000, &mut characteristics, "RESERVED");
    #[rustfmt::skip]
    add_if_includes(nt_container.dll_characteristics(), 0x8000, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE");

    println!(
        "
OPTIONAL HEADER VALUES
    magic                          : {:X} # {}
    linker version                 : {}.{}
    size of code                   : {:X}
    size of initialized data       : {:X}
    size of uninitialized data     : {:X}
    entry point                    : {:X}
    base of code                   : {:X}
    base of data                   : {:X}
    image base                     : {:X}
    section alignment              : {:X}
    file alignment                 : {:X}
    operating system version       : {}.{}
    image version                  : {}.{}
    subsystem version              : {}.{}
    Win32 version                  : {}
    size of image                  : {:X}
    size of headers                : {:X}
    checksum                       : {:X}
    subsystem                      : {:X} ({})
    DLL characteristics            : {:X}\
    ",
        nt_container.arch(),
        magic,
        nt_container.major_linker_version(),
        nt_container.minor_linker_version(),
        nt_container.size_of_code(),
        nt_container.size_of_initialized_data(),
        nt_container.size_of_uninitialized_data(),
        nt_container.address_of_entry_point(),
        nt_container.base_of_code(),
        nt_container.base_of_data(),
        nt_container.image_base(),
        nt_container.section_alignment(),
        nt_container.file_alignment(),
        nt_container.major_operating_system_version(),
        nt_container.minor_operating_system_version(),
        nt_container.major_image_version(),
        nt_container.minor_image_version(),
        nt_container.major_subsystem_version(),
        nt_container.minor_subsystem_version(),
        nt_container.win32_version_value(),
        nt_container.size_of_image(),
        nt_container.size_of_headers(),
        nt_container.checksum(),
        nt_container.subsystem(),
        subsystem,
        nt_container.dll_characteristics(),
    );

    for characteristic in characteristics {
        println!("        {}", characteristic);
    }

    println!(
        "    size of stack reserve          : {:X}
    size of stack commit           : {:X}
    size of heap reserve           : {:X}
    size of heap commit            : {:X}
    loader flags                   : {:X}
    number of dictionaries         : {:X} 
    export directory               : {:X} [{:X}]
    import directory               : {:X} [{:X}]
    resource directory             : {:X} [{:X}]
    exception directory            : {:X} [{:X}]
    certificates directory         : {:X} [{:X}]
    base relocation directory      : {:X} [{:X}]
    debug directory                : {:X} [{:X}]
    architecture directory         : {:X} [{:X}]
    global pointer directory       : {:X} [{:X}]
    thread storage directory       : {:X} [{:X}]
    load configuration directory   : {:X} [{:X}]
    bound import directory         : {:X} [{:X}]
    import address table directory : {:X} [{:X}]
    delay import directory         : {:X} [{:X}]
    COM descriptor directory       : {:X} [{:X}]
    reserved directory             : {:X} [{:X}]\
    ",
        nt_container.size_of_stack_reserve(),
        nt_container.size_of_stack_commit(),
        nt_container.size_of_heap_reserve(),
        nt_container.size_of_heap_commit(),
        nt_container.loader_flags(),
        nt_container.number_of_rva_and_sizes(),
        nt_container.data_directories()[0].virtual_address(),
        nt_container.data_directories()[0].size(),
        nt_container.data_directories()[1].virtual_address(),
        nt_container.data_directories()[1].size(),
        nt_container.data_directories()[2].virtual_address(),
        nt_container.data_directories()[2].size(),
        nt_container.data_directories()[3].virtual_address(),
        nt_container.data_directories()[3].size(),
        nt_container.data_directories()[4].virtual_address(),
        nt_container.data_directories()[4].size(),
        nt_container.data_directories()[5].virtual_address(),
        nt_container.data_directories()[5].size(),
        nt_container.data_directories()[6].virtual_address(),
        nt_container.data_directories()[6].size(),
        nt_container.data_directories()[7].virtual_address(),
        nt_container.data_directories()[7].size(),
        nt_container.data_directories()[8].virtual_address(),
        nt_container.data_directories()[8].size(),
        nt_container.data_directories()[9].virtual_address(),
        nt_container.data_directories()[9].size(),
        nt_container.data_directories()[10].virtual_address(),
        nt_container.data_directories()[10].size(),
        nt_container.data_directories()[11].virtual_address(),
        nt_container.data_directories()[11].size(),
        nt_container.data_directories()[12].virtual_address(),
        nt_container.data_directories()[12].size(),
        nt_container.data_directories()[13].virtual_address(),
        nt_container.data_directories()[13].size(),
        nt_container.data_directories()[14].virtual_address(),
        nt_container.data_directories()[14].size(),
        nt_container.data_directories()[15].virtual_address(),
        nt_container.data_directories()[15].size(),
    )
}

fn print_section_headers(container: &Container) -> () {
    let nt_container = container.nt_container().unwrap();
    let section_headers = container.section_headers().unwrap();

    for i in 0..nt_container.number_of_sections() {
        let section_header = &section_headers[i as usize];

        fn add_if_includes(flags: u32, flag: u32, vector: &mut Vec<String>, text: &str) -> () {
            if flags & flag == flag {
                vector.push(text.to_owned());
            }
        }
        let mut flags: Vec<String> = Vec::new();
        add_if_includes(section_header.characteristics(), 0x00000001, &mut flags, "RESERVED");
        add_if_includes(section_header.characteristics(), 0x00000001, &mut flags, "RESERVED");
        add_if_includes(section_header.characteristics(), 0x00000002, &mut flags, "RESERVED");
        add_if_includes(section_header.characteristics(), 0x00000004, &mut flags, "RESERVED");
        add_if_includes(section_header.characteristics(), 0x00000008, &mut flags, "IMAGE_SCN_TYPE_NO_PAD");
        add_if_includes(section_header.characteristics(), 0x00000010, &mut flags, "RESERVED");
        add_if_includes(section_header.characteristics(), 0x00000020, &mut flags, "IMAGE_SCN_CNT_CODE");
        add_if_includes(section_header.characteristics(), 0x00000040, &mut flags, "IMAGE_SCN_CNT_INITIALIZED_DATA");
        add_if_includes(section_header.characteristics(), 0x00000080, &mut flags, "IMAGE_SCN_CNT_UNINITIALIZED_DATA");
        add_if_includes(section_header.characteristics(), 0x00000100, &mut flags, "IMAGE_SCN_LNK_OTHER");
        add_if_includes(section_header.characteristics(), 0x00000200, &mut flags, "IMAGE_SCN_LNK_INFO");
        add_if_includes(section_header.characteristics(), 0x00000400, &mut flags, "RESERVED");
        add_if_includes(section_header.characteristics(), 0x00000800, &mut flags, "IMAGE_SCN_LNK_REMOVE");
        add_if_includes(section_header.characteristics(), 0x00001000, &mut flags, "IMAGE_SCN_LNK_COMDAT");
        add_if_includes(section_header.characteristics(), 0x00002000, &mut flags, "RESERVED");
        add_if_includes(section_header.characteristics(), 0x00004000, &mut flags, "IMAGE_SCN_NO_DEFER_SPEC_EXC");
        add_if_includes(section_header.characteristics(), 0x00008000, &mut flags, "IMAGE_SCN_GPREL");
        add_if_includes(section_header.characteristics(), 0x00010000, &mut flags, "RESERVED");
        add_if_includes(section_header.characteristics(), 0x00020000, &mut flags, "IMAGE_SCN_MEM_PURGEABLE");
        add_if_includes(section_header.characteristics(), 0x00040000, &mut flags, "IMAGE_SCN_MEM_LOCKED");
        add_if_includes(section_header.characteristics(), 0x00080000, &mut flags, "IMAGE_SCN_MEM_PRELOAD");
        add_if_includes(section_header.characteristics(), 0x00100000, &mut flags, "IMAGE_SCN_ALIGN_1BYTES");
        add_if_includes(section_header.characteristics(), 0x00200000, &mut flags, "IMAGE_SCN_ALIGN_2BYTES");
        add_if_includes(section_header.characteristics(), 0x00300000, &mut flags, "IMAGE_SCN_ALIGN_4BYTES");
        add_if_includes(section_header.characteristics(), 0x00400000, &mut flags, "IMAGE_SCN_ALIGN_8BYTES");
        add_if_includes(section_header.characteristics(), 0x00500000, &mut flags, "IMAGE_SCN_ALIGN_16BYTES");
        add_if_includes(section_header.characteristics(), 0x00600000, &mut flags, "IMAGE_SCN_ALIGN_32BYTES");
        add_if_includes(section_header.characteristics(), 0x00700000, &mut flags, "IMAGE_SCN_ALIGN_64BYTES");
        add_if_includes(section_header.characteristics(), 0x00800000, &mut flags, "IMAGE_SCN_ALIGN_128BYTES");
        add_if_includes(section_header.characteristics(), 0x00900000, &mut flags, "IMAGE_SCN_ALIGN_256BYTES");
        add_if_includes(section_header.characteristics(), 0x00A00000, &mut flags, "IMAGE_SCN_ALIGN_512BYTES");
        add_if_includes(section_header.characteristics(), 0x00B00000, &mut flags, "IMAGE_SCN_ALIGN_1024BYTES");
        add_if_includes(section_header.characteristics(), 0x00C00000, &mut flags, "IMAGE_SCN_ALIGN_2048BYTES");
        add_if_includes(section_header.characteristics(), 0x00D00000, &mut flags, "IMAGE_SCN_ALIGN_4096BYTES");
        add_if_includes(section_header.characteristics(), 0x00E00000, &mut flags, "IMAGE_SCN_ALIGN_8192BYTES");
        add_if_includes(section_header.characteristics(), 0x01000000, &mut flags, "IMAGE_SCN_LNK_NRELOC_OVFL");
        add_if_includes(section_header.characteristics(), 0x02000000, &mut flags, "IMAGE_SCN_MEM_DISCARDABLE");
        add_if_includes(section_header.characteristics(), 0x04000000, &mut flags, "IMAGE_SCN_MEM_NOT_CACHED");
        add_if_includes(section_header.characteristics(), 0x08000000, &mut flags, "IMAGE_SCN_MEM_NOT_PAGED");
        add_if_includes(section_header.characteristics(), 0x10000000, &mut flags, "IMAGE_SCN_MEM_SHARED");
        add_if_includes(section_header.characteristics(), 0x20000000, &mut flags, "IMAGE_SCN_MEM_EXECUTE");
        add_if_includes(section_header.characteristics(), 0x40000000, &mut flags, "IMAGE_SCN_MEM_READ");
        add_if_includes(section_header.characteristics(), 0x80000000, &mut flags, "IMAGE_SCN_MEM_WRITE");

        println!(
            "
SECTION HEADER #{}
    name                             : {}
    virtual size                     : {:X}
    virtual address                  : {:X}
    size of raw data                 : {:X}
    file pointer to raw data         : {:X}
    file pointer to relocation table : {:X}
    file pointer to line numbers     : {:X}
    number of relocations            : {:X}
    number of line numbers           : {:X}
    flags                            : {:X}\
        ",
            i + 1,
            section_header.name(),
            section_header.virtual_size(),
            section_header.virtual_address(),
            section_header.size_of_raw_data(),
            section_header.pointer_to_raw_data(),
            section_header.pointer_to_relocations(),
            section_header.pointer_to_linenumbers(),
            section_header.number_of_relocations(),
            section_header.number_of_linenumbers(),
            section_header.characteristics(),
        );

        for flag in flags {
            println!("        {}", flag);
        }
    }
}
