use std::iter::repeat;

use roki::containers::ImportDescriptor;
use roki::Executable;

pub fn print(executable: &Executable) -> () {
    let import_data = match executable.import_data() {
        Some(import_data) => import_data,
        None => return,
    };

    let descriptors: Vec<&ImportDescriptor> = import_data.descriptors();

    for i in 0..descriptors.len() {
        let descriptor = descriptors[i];

        println!(
            "
IMPORT DESCRIPTOR #{}
    time date stamps : {:#010X}
    name             : {}
",
            i + 1,
            descriptor.time_date_stamp(),
            descriptor.name()
        );

        let functions = descriptor.functions();
        let the_longest_function_length = functions.iter().max_by_key(|w| w.name().len()).unwrap().name().len();

        fn alignment_strings(string: &str, times: usize) -> String {
            repeat(string).take(times).collect::<String>()
        }

        println!("    IMPORT FUNCTIONS");
        println!("    +-{}-+--------+------------+", alignment_strings("-", the_longest_function_length));
        println!("    | Name {} | Hint   | Address    |", alignment_strings(" ", the_longest_function_length - 5));
        println!("    +-{}-+--------+------------+", alignment_strings("-", the_longest_function_length));

        for i in 0..functions.len() {
            let function = functions[i as usize];
            let name = function.name();
            let hint = match function.hint() {
                Some(hint) => format!("{:#06X}", hint),
                None => format!("{:<6}", " "),
            };

            let spaces = alignment_strings(" ", the_longest_function_length - name.len());
            println!("    | {}{} | {:<6} | {:#010X} |", name, spaces, hint, function.address());
            println!("    +-{}-+--------+------------+", alignment_strings("-", the_longest_function_length));
        }
    }
}
