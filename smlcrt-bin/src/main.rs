#[macro_use]
extern crate clap;

use clap::{App, SubCommand, Arg};
fn main() {
    let matches = App::new("smlcrt")
        .author("Till Klocke")
        .version(crate_version!())
        .author(crate_authors!())
        .subcommand(
            SubCommand::with_name("create")
            .args(&[
                Arg::with_name("subject")
                    .help("The subject of the new certificate")
                    .short("s")
                    .long("subject")
                    .required(true)
                    .takes_value(true),
                Arg::with_name("serialnumber")
                    .help("The serial number to assign to this certificate")
                    .short("n")
                    .long("serialnumber")
                    .required(true)
                    .takes_value(true)
                    .validator(validate_serialnumber),
            ])
            )
        .get_matches();

    match matches.subcommand_name() {
        Some("create") => create_certificate(),
        _ => println!("Unknown subcommand"),
    }
}

fn validate_serialnumber(v: String) -> Result<(), String> {
    if !v.parse::<u64>().is_ok() {
        Err(String::from("This is not a valid unsigned integer"))
    } else {
        Ok(())
    }
}

fn create_certificate() {

}
