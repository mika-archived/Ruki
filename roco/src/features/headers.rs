use roki::Executable;

pub fn print(executable: &Executable) -> () {
    print_file_header(executable);
    print_optional_header(executable);
    print_section_headers(executable);
}

fn print_file_header(executable: &Executable) -> () {
    let file_header = executable.file_header().unwrap();

    let machine = match file_header.machine() {
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
    add_if_includes(file_header.characteristics(), 0x0001, &mut characteristics, "IMAGE_FILE_RELOCS_STRIPPED");
    add_if_includes(file_header.characteristics(), 0x0002, &mut characteristics, "IMAGE_FILE_EXECUTABLE_IMAGE");
    add_if_includes(file_header.characteristics(), 0x0004, &mut characteristics, "IMAGE_FILE_LINE_NUMS_STRIPPED");
    add_if_includes(file_header.characteristics(), 0x0008, &mut characteristics, "IMAGE_FILE_LOCAL_SYMS_STRIPPED");
    add_if_includes(file_header.characteristics(), 0x0010, &mut characteristics, "IMAGE_FILE_AGGRESIVE_WS_TRIM");
    add_if_includes(file_header.characteristics(), 0x0020, &mut characteristics, "IMAGE_FILE_LARGE_ADDRESS_AWARE");
    add_if_includes(file_header.characteristics(), 0x0080, &mut characteristics, "IMAGE_FILE_BYTES_REVERSED_LO");
    add_if_includes(file_header.characteristics(), 0x0100, &mut characteristics, "IMAGE_FILE_32BIT_MACHINE");
    add_if_includes(file_header.characteristics(), 0x0200, &mut characteristics, "IMAGE_FILE_DEBUG_STRIPPED");
    add_if_includes(file_header.characteristics(), 0x0400, &mut characteristics, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP");
    add_if_includes(file_header.characteristics(), 0x0800, &mut characteristics, "IMAGE_FILE_NET_RUN_FROM_SWAP");
    add_if_includes(file_header.characteristics(), 0x1000, &mut characteristics, "IMAGE_FILE_SYSTEM");
    add_if_includes(file_header.characteristics(), 0x2000, &mut characteristics, "IMAGE_FILE_DLL");
    add_if_includes(file_header.characteristics(), 0x4000, &mut characteristics, "IMAGE_FILE_UP_SYSTEM_ONLY");
    add_if_includes(file_header.characteristics(), 0x8000, &mut characteristics, "IMAGE_FILE_BYTES_REVERSED_HI");

    println!(
        "
FILE HEADER VALUES
    machine                      : {:#06X} ({})
    number of sections           : {:#010X}
    time date stamps             : {:#010X}
    file pointer to symbol table : {:#010X}
    number of symbols            : {:#010X}
    size of optional header      : {:#010X}
    characteristics              : {:#010X}\
    ",
        file_header.machine(),
        machine,
        file_header.number_of_sections(),
        file_header.time_date_stamps(),
        file_header.pointer_to_symbol_table(),
        file_header.number_of_symbols(),
        file_header.size_of_optional_header(),
        file_header.characteristics(),
    );

    for characteristic in characteristics {
        println!("        {}", characteristic);
    }
}

fn print_optional_header(executable: &Executable) -> () {
    let optional_header = executable.optional_header().unwrap();

    let magic = match optional_header.magic() {
        0x10b => "PE32  (x86)",
        0x20b => "PE32+ (x64)",
        0x107 => "ROM",
        _ => "Unknown",
    };
    let subsystem = match optional_header.subsystem() {
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
    add_if_includes(optional_header.dll_characteristics(), 0x0001, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_PROCESS_INIT");
    add_if_includes(optional_header.dll_characteristics(), 0x0002, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_PROCESS_TERM");
    add_if_includes(optional_header.dll_characteristics(), 0x0004, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_THREAD_INIT");
    add_if_includes(optional_header.dll_characteristics(), 0x0008, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_THREAD_TERM");
    add_if_includes(optional_header.dll_characteristics(), 0x0020, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA");
    add_if_includes(optional_header.dll_characteristics(), 0x0040, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE");
    add_if_includes(optional_header.dll_characteristics(), 0x0080, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY");
    add_if_includes(optional_header.dll_characteristics(), 0x0100, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT");
    add_if_includes(optional_header.dll_characteristics(), 0x0200, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION");
    add_if_includes(optional_header.dll_characteristics(), 0x0400, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_NO_SEH");
    add_if_includes(optional_header.dll_characteristics(), 0x0800, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_NO_BIND");
    add_if_includes(optional_header.dll_characteristics(), 0x1000, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_APP_CONTAINER");
    add_if_includes(optional_header.dll_characteristics(), 0x2000, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER");
    add_if_includes(optional_header.dll_characteristics(), 0x4000, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_GUARD_CF");
    #[rustfmt::skip]
    add_if_includes(optional_header.dll_characteristics(), 0x8000, &mut characteristics, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE");

    println!(
        "
OPTIONAL HEADER VALUES
    magic                          : {:#06X} # {}
    linker version                 : {}.{}
    size of code                   : {:#010X}
    size of initialized data       : {:#010X}
    size of uninitialized data     : {:#010X}
    entry point                    : {:#010X}
    base of code                   : {:#010X}
    base of data                   : {:#010X}
    image base                     : {:#014X}
    section alignment              : {:#010X}
    file alignment                 : {:#010X}
    operating system version       : {}.{}
    image version                  : {}.{}
    subsystem version              : {}.{}
    Win32 version                  : {}
    size of image                  : {:#010X}
    size of headers                : {:#010X}
    checksum                       : {:#010X}
    subsystem                      : {:#06X} ({})
    DLL characteristics            : {:#010X}\
    ",
        optional_header.magic(),
        magic,
        optional_header.major_linker_version(),
        optional_header.minor_linker_version(),
        optional_header.size_of_code(),
        optional_header.size_of_initialized_data(),
        optional_header.size_of_uninitialized_data(),
        optional_header.address_of_entry_point(),
        optional_header.base_of_code(),
        optional_header.base_of_data(),
        optional_header.image_base(),
        optional_header.section_alignment(),
        optional_header.file_alignment(),
        optional_header.major_operating_system_version(),
        optional_header.minor_operating_system_version(),
        optional_header.major_image_version(),
        optional_header.minor_image_version(),
        optional_header.major_subsystem_version(),
        optional_header.minor_subsystem_version(),
        optional_header.win32_version_value(),
        optional_header.size_of_image(),
        optional_header.size_of_headers(),
        optional_header.checksum(),
        optional_header.subsystem(),
        subsystem,
        optional_header.dll_characteristics(),
    );

    for characteristic in characteristics {
        println!("        {}", characteristic);
    }

    println!(
        "    size of stack reserve          : {:#014X}
    size of stack commit           : {:#014X}
    size of heap reserve           : {:#014X}
    size of heap commit            : {:#014X}
    loader flags                   : {:#010X}
    number of dictionaries         : {:#06X} 
    export directory               : {:#010X} [{:#010X}]
    import directory               : {:#010X} [{:#010X}]
    resource directory             : {:#010X} [{:#010X}]
    exception directory            : {:#010X} [{:#010X}]
    certificates directory         : {:#010X} [{:#010X}]
    base relocation directory      : {:#010X} [{:#010X}]
    debug directory                : {:#010X} [{:#010X}]
    architecture directory         : {:#010X} [{:#010X}]
    global pointer directory       : {:#010X} [{:#010X}]
    thread storage directory       : {:#010X} [{:#010X}]
    load configuration directory   : {:#010X} [{:#010X}]
    bound import directory         : {:#010X} [{:#010X}]
    import address table directory : {:#010X} [{:#010X}]
    delay import directory         : {:#010X} [{:#010X}]
    COM descriptor directory       : {:#010X} [{:#010X}]
    reserved directory             : {:#010X} [{:#010X}]\
    ",
        optional_header.size_of_stack_reserve(),
        optional_header.size_of_stack_commit(),
        optional_header.size_of_heap_reserve(),
        optional_header.size_of_heap_commit(),
        optional_header.loader_flags(),
        optional_header.number_of_rva_and_sizes(),
        optional_header.data_directories()[0].virtual_address(),
        optional_header.data_directories()[0].size(),
        optional_header.data_directories()[1].virtual_address(),
        optional_header.data_directories()[1].size(),
        optional_header.data_directories()[2].virtual_address(),
        optional_header.data_directories()[2].size(),
        optional_header.data_directories()[3].virtual_address(),
        optional_header.data_directories()[3].size(),
        optional_header.data_directories()[4].virtual_address(),
        optional_header.data_directories()[4].size(),
        optional_header.data_directories()[5].virtual_address(),
        optional_header.data_directories()[5].size(),
        optional_header.data_directories()[6].virtual_address(),
        optional_header.data_directories()[6].size(),
        optional_header.data_directories()[7].virtual_address(),
        optional_header.data_directories()[7].size(),
        optional_header.data_directories()[8].virtual_address(),
        optional_header.data_directories()[8].size(),
        optional_header.data_directories()[9].virtual_address(),
        optional_header.data_directories()[9].size(),
        optional_header.data_directories()[10].virtual_address(),
        optional_header.data_directories()[10].size(),
        optional_header.data_directories()[11].virtual_address(),
        optional_header.data_directories()[11].size(),
        optional_header.data_directories()[12].virtual_address(),
        optional_header.data_directories()[12].size(),
        optional_header.data_directories()[13].virtual_address(),
        optional_header.data_directories()[13].size(),
        optional_header.data_directories()[14].virtual_address(),
        optional_header.data_directories()[14].size(),
        optional_header.data_directories()[15].virtual_address(),
        optional_header.data_directories()[15].size(),
    )
}

fn print_section_headers(executable: &Executable) -> () {
    let file_header = executable.file_header().unwrap();
    let section_headers = executable.section_headers().unwrap();

    for i in 0..file_header.number_of_sections() {
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
    virtual size                     : {:#010X}
    virtual address                  : {:#010X}
    size of raw data                 : {:#010X}
    file pointer to raw data         : {:#010X}
    file pointer to relocation table : {:#010X}
    file pointer to line numbers     : {:#010X}
    number of relocations            : {:#010X}
    number of line numbers           : {:#010X}
    flags                            : {:#010X}\
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
