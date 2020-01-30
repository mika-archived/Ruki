use std::iter::repeat;

use roki::Executable;

pub fn print(executable: &Executable) -> () {
    let export_data = match executable.export_data() {
        Some(export_data) => export_data,
        None => return,
    };

    let directory = export_data.directory();

    println!(
        "
EXPORT DIRECTORY
    name                     : {}
    base ordinal             : {}
    number of functions      : {}
    number of names          : {}
    address of functions     : {:#010X}
    address of names         : {:#010X}
    address of name ordinals : {:#010X}
    ",
        directory.name(),
        directory.base(),
        directory.number_of_functions(),
        directory.number_of_names(),
        directory.address_of_functions(),
        directory.address_of_names(),
        directory.address_of_name_ordinals(),
    );

    let functions = match export_data.functions() {
        Some(functions) => functions,
        None => return,
    };

    let the_longest_function_length = functions.iter().max_by_key(|w| w.name().len()).unwrap().name().len();

    fn alignment_strings(string: &str, times: usize) -> String {
        repeat(string).take(times).collect::<String>()
    }

    println!("    EXPORT FUNCTIONS");
    println!("    +-{}-+---------+------------+", alignment_strings("-", the_longest_function_length));
    println!("    | Name {} | Ordinal |  Address   |", alignment_strings(" ", the_longest_function_length - 5));
    println!("    +-{}-+---------+------------+", alignment_strings("-", the_longest_function_length));

    for i in 0..functions.len() {
        let function = functions[i as usize];
        let name = function.name();
        let spaces = alignment_strings(" ", the_longest_function_length - name.len());

        println!("    | {}{} | {:<7} | {:#010X} |", name, spaces, function.ordinal(), function.function());
        println!("    +-{}-+---------+------------+", alignment_strings("-", the_longest_function_length));
    }
}
