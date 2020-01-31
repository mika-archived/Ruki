use roki::Executable;

pub fn print(executable: &Executable) -> () {
    let debug_data = match executable.debug_data() {
        Some(debug_data) => debug_data,
        None => return,
    };

    println!("\nDEBUG DIRECTORIES");

    for i in 0..debug_data.len() {
        let debug_container = debug_data[i];
        let directory = debug_container.directory();

        let format = match directory.r#type() {
            1 => "COFF",
            2 => "CodeView",
            3 => "FPO",
            4 => "Miscellaneous",
            5 => "Exception",
            6 => "Fixup",
            7 => "To src",
            8 => "From src",
            9 => "Borland",
            10 => "RESERVED10",
            11 => "CLSID",
            12 => "VC Feature",
            13 => "POGO",
            14 => "ILTCG",
            15 => "MPX",
            16 => "Repro",
            _ => "Unknown",
        };

        println!(
            "
    DEBUG INFORMATION #{}
        type                : {}
        version             : {}.{}
        timestamp           : {:#010X}
        characteristics     : {:#010X}
        size                : {}
        RVA                 : {:#010X}
        offset              : {:#010X}\
        ",
            i,
            format,
            directory.major_version(),
            directory.minor_version(),
            directory.time_date_stamp(),
            directory.characteristics(),
            directory.size_of_data(),
            directory.address_of_raw_data(),
            directory.pointer_to_raw_data(),
        );

        // CodeView has more data
        if directory.r#type() == 0x02 {
            let code_view = debug_container.code_view().unwrap();
            let format = match code_view.format() {
                // seel: https://github.com/llvm/llvm-project/blob/77e6bb3cbad26f0a95be5c427fa7f87833d5843e/llvm/include/llvm/Object/CVDebugRecord.h#L18-L21
                0x53445352 => "RSDS (PDB 7.0)",
                _ => "Unsupported",
            };

            println!(
                "        code view format    : {}
        GUID                : {}
        age                 : {}
        PDB path            : {}\
    ",
                format,
                code_view.guid(),
                code_view.age(),
                code_view.path()
            )
        }
    }
}
