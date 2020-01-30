use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg};

pub fn build_app() -> App<'static, 'static> {
    App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::with_name("all").long("all").help("display all available information expect code disassembly"))
        .arg(Arg::with_name("archive_members").long("archive-members").help("display minimal information about member objects"))
        .arg(Arg::with_name("clr_header").long("clr-header").help("display CLR specific information"))
        .arg(Arg::with_name("clr_container").long("clr").help("display CLR specific information that contains metadata"))
        .arg(Arg::with_name("debug").long("debug").help("display the dump of debug information"))
        .arg(Arg::with_name("dependents").long("dependents").help("display the names of the DLLs from which the image imports functions"))
        .arg(Arg::with_name("directives").long("directives").help("display the compiler-generated .directives section"))
        .arg(Arg::with_name("exports").long("exports").help("display all definitions that exported from the image"))
        .arg(Arg::with_name("fpo").long("fpo").help("display frame pointer optimization (FPO) records"))
        .arg(Arg::with_name("headers").long("headers").help("display the file header and the header for each sections"))
        .arg(Arg::with_name("imports").long("imports").help("display the list of DLLs that are imported to and all the imports from each DLLs"))
        .arg(Arg::with_name("load_config").long("load-config").help("display the dump of the loader configuration"))
        .arg(Arg::with_name("tls").long("tls").help("display the dump of tls"))
        .arg(Arg::with_name("path").required(true).takes_value(true))
}
