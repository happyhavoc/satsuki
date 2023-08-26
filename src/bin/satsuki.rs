use std::{
    error::Error,
    path::{Path, PathBuf},
};

use argh::FromArgs;
use capstone::{
    arch::x86::{ArchMode, ArchSyntax},
    prelude::{BuildsCapstone, BuildsCapstoneSyntax},
    Capstone,
};
use satsuki::{Executable, Mapping};

#[derive(FromArgs, PartialEq, Debug)]
/// Top-level command.
struct TopLevel {
    #[argh(subcommand)]
    subcommand: SubCommandEnum,

    /// mapping TOML file related to the executable.
    #[argh(option)]
    mapping_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommandEnum {
    Disassemble(DisassembleSubCommand),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Disassemble a function by name.
#[argh(subcommand, name = "disassemble")]
struct DisassembleSubCommand {
    /// executable file to disassemble.
    #[argh(positional)]
    executable_file: PathBuf,

    /// the function name to disassemble.
    #[argh(positional)]
    function_name: String,

    /// pdb file related to the executable.
    #[argh(option)]
    pdb_file: Option<PathBuf>,

    /// force usage of address zero when disassembling.
    #[argh(switch)]
    force_address_zero: bool,

    /// use at&t syntax when printing assembly.
    #[argh(switch)]
    att: bool,
}

fn parse_object_with_mapping(
    executable_file: &Path,
    mapping: Mapping,
) -> Result<Executable, Box<dyn Error>> {
    if !executable_file.exists() {
        eprintln!("Executable not found!\n");
        std::process::exit(1);
    }

    let raw_data = std::fs::read(executable_file)?;
    let raw_obj = object::File::parse(&*raw_data)?;
    let executable = satsuki::Executable::from_object_with_mapping(&raw_obj, mapping)?;

    Ok(executable)
}

fn parse_object_with_pdb(
    executable_file: &Path,
    pdb_file: &Path,
    mapping: Mapping,
) -> Result<Executable, Box<dyn Error>> {
    if !executable_file.exists() {
        eprintln!("Executable not found!\n");
        std::process::exit(1);
    }

    if !pdb_file.exists() {
        eprintln!("PDB not found!\n");
        std::process::exit(1);
    }

    let raw_data = std::fs::read(executable_file)?;
    let raw_obj = object::File::parse(&*raw_data)?;
    let pdb_file = pdb::PDB::open(std::fs::File::open(pdb_file)?)?;
    let executable = satsuki::Executable::from_object_with_pdb(&raw_obj, mapping, pdb_file)?;

    Ok(executable)
}

fn handle_disassemble(
    mapping: Mapping,
    args: &DisassembleSubCommand,
) -> Result<(), Box<dyn Error>> {
    let capstone = Capstone::new()
        .x86()
        .mode(ArchMode::Mode32)
        .syntax(if args.att {
            ArchSyntax::Att
        } else {
            ArchSyntax::Intel
        })
        .detail(true)
        .build()
        .expect("Cannot create Capstone context");

    let executable;

    if let Some(pdb_file) = &args.pdb_file {
        executable = parse_object_with_pdb(&args.executable_file, pdb_file, mapping)?;
    } else {
        executable = parse_object_with_mapping(&args.executable_file, mapping)?;
    }

    match executable.get_function(&args.function_name) {
        Some(function) => {
            let res = function
                .disassemble(&capstone, args.force_address_zero)
                .unwrap();

            println!("{}", res);
        }
        None => {
            eprintln!("Function {} not found in executable!", args.function_name);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: TopLevel = argh::from_env();

    if !args.mapping_file.exists() {
        eprintln!("Mapping not found!\n");
        std::process::exit(1);
    }

    let raw_mapping = std::fs::read_to_string(args.mapping_file)?;
    let mapping = toml::from_str::<Mapping>(&raw_mapping)?;

    match &args.subcommand {
        SubCommandEnum::Disassemble(disassemble_args) => {
            handle_disassemble(mapping, disassemble_args)
        }
    }
}
