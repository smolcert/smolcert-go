#[macro_use]
extern crate clap;

use clap::{App, SubCommand, Arg, ArgMatches};

use std::path::Path;
use canonical_path::*;
use rand::rngs::OsRng;
use ed25519_dalek::{Keypair, SecretKey};
use chrono::DateTime;
use smolcert::{Certificate, Validity, Extension, SIGN_CERTIFICATE};

mod errors;

use crate::errors::*;

type Result<T> = core::result::Result<T, Error>;

fn main() {
    let matches = App::new("smlcrt")
        .author("Till Klocke")
        .version(crate_version!())
        .author(crate_authors!())
        .subcommand(
            SubCommand::with_name("create")
            .about("Creates a new Smolcert")
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
                Arg::with_name("self_signed")
                    .help("Create a self signed certificates")
                    .long("selfsigned")
                    .required(false)
                    .conflicts_with("client")
                    .conflicts_with("server"),
                Arg::with_name("client")
                    .help("Create a certificate identifying a client")
                    .long("client")
                    .required(false)
                    .conflicts_with("self_signed")
                    .conflicts_with("server"),
                Arg::with_name("server")
                    .help("Create a certificate identifying a server")
                    .long("server")
                    .required(false)
                    .conflicts_with("self_signed")
                    .conflicts_with("client"),
                Arg::with_name("out_name")
                    .help("Base name where to write the certificate and the private key")
                    .long("out")
                    .required(true),
                Arg::with_name("not_before")
                    .help("Date after which the certificate is valid")
                    .required(false)
                    .long("not-before")
                    .validator(validate_date)
                    .takes_value(true),
                Arg::with_name("not_after")
                    .help("Date before which the certificate is valid")
                    .required(false)
                    .long("not-after")
                    .validator(validate_date)
                    .takes_value(true),
                Arg::with_name("issuer_cert")
                    .help("Issuing certificate this certificate should not be self signed")
                    // FIXME make this conditionally required with client and server
                    .long("issuer-cert")
                    .takes_value(true),
                Arg::with_name("issuer_key")
                    .help("Private key of the issuer")
                    .long("issuer-key")
                    .takes_value(true),
            ])
            )
        .get_matches();

    match matches.subcommand() {
        ("create", Some(sub_m)) => create_certificate(sub_m).unwrap(),
        _ => println!("Unknown subcommand"),
    }
}

fn validate_date(_v: String) -> std::result::Result<(), String> {
    // TODO actually validate date strings
    Ok(())
}

fn validate_serialnumber(v: String) -> std::result::Result<(), String> {
    if !v.parse::<u64>().is_ok() {
        Err(String::from("This is not a valid unsigned integer"))
    } else {
        Ok(())
    }
}

fn create_certificate(matches: &ArgMatches) -> Result<()> {
    println!("Creating certificate");

    let subject = matches.value_of("subject").unwrap();
    let client_cert = matches.is_present("client");
    let server_cert = matches.is_present("server");
    let self_signed = matches.is_present("self_signed");
    let serial_number_str = matches.value_of("serialnumber").ok_or(Error::new("Serialnumber is missing".to_string()))?;
    let serial_number : u64 = serial_number_str.parse()?;

    let out_base_name = matches.value_of("out_name").ok_or(Error::new("Out base path is missing".to_string()))?;

    let mut validity = Validity::empty();

    if let Some(not_before_str) = matches.value_of("not_before") {
        let not_before = DateTime::parse_from_rfc3339(&not_before_str)?;
        validity.not_before = not_before.timestamp() as u64;
    }

    if let Some(not_after_str) = matches.value_of("not_after") {
        let not_after = DateTime::parse_from_rfc3339(&not_after_str)?;
        validity.not_after = not_after.timestamp() as u64;
    }

    let mut csprng = OsRng{};
    let cert_keypair: Keypair = Keypair::generate(&mut csprng);

    if self_signed {
        let cert = Certificate::new_self_signed(serial_number, 
            &subject, validity, &subject, vec![Extension::KeyUsage(SIGN_CERTIFICATE)], 
            &cert_keypair)?;
        write_cert_and_key_to_disk(&cert, &cert_keypair.secret, &out_base_name)?;
    } else {
        return Err(Error::new("unsupported".to_string()));
    }
    Ok(())
}

fn write_cert_and_key_to_disk<'a>(
    cert: &'a Certificate, 
    priv_key: &SecretKey, 
    out_base_name: &str) -> Result<()> 
{
    let base_path = CanonicalPath::new(Path::new(out_base_name))?;
    let _cert_path = base_path.with_extension("smlcrt")?;
    let _key_path = base_path.with_extension("smlkey")?;
    Ok(())
}
