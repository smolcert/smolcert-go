#[macro_use]
extern crate clap;


fn main() {
    let matches = clap_app!(myapp =>
        (version: "0.1")
        (author: "Till Klocke")
        (about: "Creates, validates and manages smolcerts")
        (@arg CONFIG: -c --config +takes_value "Sets a custom config file")
        (@arg INPUT: +required "Sets the input file to use")
        (@arg debug: -d ... "Sets the level of debugging information")
        (@subcommand create =>
            (about: "creates new certificates")
            (@arg subject: -s --subject "The subject of the certificate")
            (@arg serial_number: -sn --serial-number "The serial number of the certificate")
        )
    )
    .get_matches();
}
