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

    print_file_headers(&mut container);
    print_optional_headers(&mut container);

    Ok(())
}

fn print_file_headers(container: &mut Container) -> () {
    let nt_container = container.nt_container().unwrap();

    let machine = match nt_container.machine() {
        0x014C => "x86",
        0x0200 => "Intel IPF",
        0x8664 => "x64",
        _ => "Unknown",
    };

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
}

fn print_optional_headers(container: &mut Container) -> () {
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
    DLL characteristics            : {:X}
    size of stack reserve          : {:X}
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
    reserved directory             : {:X} [{:X}]
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
        nt_container.size_of_stack_reserve(),
        nt_container.size_of_stack_commit(),
        nt_container.size_of_heap_reserve(),
        nt_container.size_of_heap_commit(),
        nt_container.loader_flags(),
        nt_container.number_of_rva_and_sizes(),
        nt_container.data_dictionary()[0].virtual_address(),
        nt_container.data_dictionary()[0].size(),
        nt_container.data_dictionary()[1].virtual_address(),
        nt_container.data_dictionary()[1].size(),
        nt_container.data_dictionary()[2].virtual_address(),
        nt_container.data_dictionary()[2].size(),
        nt_container.data_dictionary()[3].virtual_address(),
        nt_container.data_dictionary()[3].size(),
        nt_container.data_dictionary()[4].virtual_address(),
        nt_container.data_dictionary()[4].size(),
        nt_container.data_dictionary()[5].virtual_address(),
        nt_container.data_dictionary()[5].size(),
        nt_container.data_dictionary()[6].virtual_address(),
        nt_container.data_dictionary()[6].size(),
        nt_container.data_dictionary()[7].virtual_address(),
        nt_container.data_dictionary()[7].size(),
        nt_container.data_dictionary()[8].virtual_address(),
        nt_container.data_dictionary()[8].size(),
        nt_container.data_dictionary()[9].virtual_address(),
        nt_container.data_dictionary()[9].size(),
        nt_container.data_dictionary()[10].virtual_address(),
        nt_container.data_dictionary()[10].size(),
        nt_container.data_dictionary()[11].virtual_address(),
        nt_container.data_dictionary()[11].size(),
        nt_container.data_dictionary()[12].virtual_address(),
        nt_container.data_dictionary()[12].size(),
        nt_container.data_dictionary()[13].virtual_address(),
        nt_container.data_dictionary()[13].size(),
        nt_container.data_dictionary()[14].virtual_address(),
        nt_container.data_dictionary()[14].size(),
        nt_container.data_dictionary()[15].virtual_address(),
        nt_container.data_dictionary()[15].size(),
    )
}
