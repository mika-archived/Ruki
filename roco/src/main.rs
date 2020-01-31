use std::path::Path;

use clap::ArgMatches;

mod app;
mod features;

use crate::features::*;
use exitfailure::ExitFailure;
use roki::Executable;

fn main() -> Result<(), ExitFailure> {
    let matches = app::build_app().get_matches();

    run(matches)?;
    Ok(())
}

fn run(matches: ArgMatches<'static>) -> Result<(), failure::Error> {
    let path = Path::new(matches.value_of("path").unwrap());

    // check file existence
    if !path.exists() || !path.is_file() {
        let msg = format!("Path `{}` is no such file or executable file", path.display());
        return Err(failure::err_msg(msg));
    }

    // create EXE container
    let mut executable = Executable::new(path)?;
    executable.parse()?;

    if matches.is_present("exports") {
        print_exports(&executable);
    }
    if matches.is_present("debug") {
        print_debug_directory(&executable);
    }
    if matches.is_present("headers") {
        print_headers(&executable);
    }
    if matches.is_present("imports") {
        print_imports(&executable);
    }

    Ok(())
}
