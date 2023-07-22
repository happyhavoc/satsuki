use std::{error::Error, path::PathBuf};

use argh::FromArgs;
use capstone::{
    arch::x86::{ArchMode, ArchSyntax},
    prelude::{BuildsCapstone, BuildsCapstoneSyntax},
    Capstone,
};
use satsuki::Mapping;

#[derive(FromArgs)]
/// Disassemble a function by name.
struct Args {
    /// executable file to disassemble.
    #[argh(positional)]
    executable_file: PathBuf,

    /// the function name to disassemble.
    #[argh(positional)]
    function_name: String,

    /// pdb file related to the executable.
    #[argh(option)]
    pdb_file: Option<PathBuf>,

    /// mapping TOML file related to the executable.
    #[argh(option)]
    mapping_file: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let capstone = Capstone::new()
        .x86()
        .mode(ArchMode::Mode32)
        .syntax(ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Cannot create Capstone context");

    let args: Args = argh::from_env();

    if !args.executable_file.exists() {
        eprintln!("Executable not found!\n");
        std::process::exit(1);
    }

    if let Some(pdb_file) = args.pdb_file {
        if !pdb_file.exists() {
            eprintln!("PDB not found!\n");
            std::process::exit(1);
        }

        let bin_data = std::fs::read(args.executable_file)?;
        let raw_obj = object::File::parse(&*bin_data)?;
        let pdb_file = pdb::PDB::open(std::fs::File::open(pdb_file)?)?;

        let executable = satsuki::Executable::from_object_with_pdb(&raw_obj, pdb_file).unwrap();

        match executable.get_function(&args.function_name) {
            Some(function) => {
                let res = function.disassemble(&capstone).unwrap();

                println!("{}", res);
            }
            None => {
                eprintln!("Function {} not found in executable!", args.function_name);
                std::process::exit(1);
            }
        }

        return Ok(());
    }

    if let Some(mapping_file) = args.mapping_file {
        if !mapping_file.exists() {
            eprintln!("Mapping not found!\n");
            std::process::exit(1);
        }

        let bin_data = std::fs::read(args.executable_file)?;
        let raw_obj = object::File::parse(&*bin_data)?;
        let raw_mapping = std::fs::read_to_string(mapping_file)?;
        let mapping = toml::from_str::<Mapping>(&raw_mapping)?;

        let executable = satsuki::Executable::from_object_with_mapping(&raw_obj, mapping).unwrap();

        match executable.get_function(&args.function_name) {
            Some(function) => {
                let res = function.disassemble(&capstone).unwrap();

                println!("{}", res);
            }
            None => {
                eprintln!("Function {} not found in executable!", args.function_name);
                std::process::exit(1);
            }
        }

        return Ok(());
    }

    eprintln!("You must pass --pdb-file for --mapping-file\n");
    std::process::exit(1)
}
