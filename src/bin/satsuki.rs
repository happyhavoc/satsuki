use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::Write,
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
    Stats(StatsSubCommand),
    Badge(BadgeSubCommand),
}

/// Stats
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "stats")]
struct StatsSubCommand {
    /// original executable file to disassemble.
    #[argh(positional)]
    original_executable_file: PathBuf,

    /// reimplementation executable file to disassemble.
    #[argh(positional)]
    reimplementation_executable_file: PathBuf,

    /// pdb file related to the reimplementation executable.
    #[argh(positional)]
    pdb_file: PathBuf,

    /// output file containing the stats.
    #[argh(option)]
    output_file: Option<PathBuf>,
}

/// Generate a badge to be used on README.md.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "badge")]
struct BadgeSubCommand {
    /// original executable file to disassemble.
    #[argh(positional)]
    original_executable_file: PathBuf,

    /// reimplementation executable file to disassemble.
    #[argh(positional)]
    reimplementation_executable_file: PathBuf,

    /// pdb file related to the reimplementation executable.
    #[argh(positional)]
    pdb_file: PathBuf,

    /// output file containing the badge json.
    #[argh(positional)]
    output_file: PathBuf,
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

    /// enable name resolution for calls.
    #[argh(switch)]
    resolve_names: bool,
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
                .disassemble(
                    &capstone,
                    &executable,
                    args.force_address_zero,
                    args.resolve_names,
                )
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

fn remap_report_value(data: (&String, &Option<f32>)) -> (String, String) {
    let (key, value) = data;
    if let Some(value) = value {
        (key.clone(), format!("{value}%"))
    } else {
        (key.clone(), "MISSING".into())
    }
}

fn handle_stats_report(mapping: Mapping, args: &StatsSubCommand) -> Result<(), Box<dyn Error>> {
    let original_executable =
        parse_object_with_mapping(&args.original_executable_file, mapping.clone())?;
    let reimplement_executable = parse_object_with_pdb(
        &args.reimplementation_executable_file,
        &args.pdb_file,
        mapping.clone(),
    )?;

    let mut global_match = 0.0;

    let stats: HashMap<String, String> = original_executable
        .generate_stats(&reimplement_executable)
        .iter()
        .map(|x| {
            if let Some(value) = x.1 {
                global_match += value;
            }

            remap_report_value(x)
        })
        .collect();

    let global_raw_diff = global_match / original_executable.functions_count() as f32;

    if let Some(output_file) = &args.output_file {
        let mut file = File::create(output_file)?;

        match output_file.extension() {
            Some(test) if test.to_string_lossy() == "csv" => {
                writeln!(file, "\"Function name\",\"Status\"")?;

                for (key, value) in stats {
                    writeln!(file, "\"{key}\",\"{value}\"")?;
                }
            }
            _ => {
                for (key, value) in stats {
                    writeln!(file, "{key}: {value}")?;
                }
            }
        }
    } else {
        for (key, value) in stats {
            println!("{key}: {value}")
        }
    }

    println!("GLOBAL: {global_raw_diff}%");

    Ok(())
}

fn handle_badge(mapping: Mapping, args: &BadgeSubCommand) -> Result<(), Box<dyn Error>> {
    let original_executable =
        parse_object_with_mapping(&args.original_executable_file, mapping.clone())?;
    let reimplement_executable = parse_object_with_pdb(
        &args.reimplementation_executable_file,
        &args.pdb_file,
        mapping.clone(),
    )?;

    let mut global_match = 0.0;

    for (_, value) in original_executable.generate_stats(&reimplement_executable) {
        global_match += value.unwrap_or(0.0);
    }

    let global_raw_diff = global_match / original_executable.functions_count() as f32;
    let mut file = File::create(&args.output_file)?;
    writeln!(file, "{{\"schemaVersion\": 1, \"label\": \"progress\", \"message\": \"{:.1$}%\", \"color\": \"yellow\"}}", global_raw_diff, 2)?;

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
        SubCommandEnum::Disassemble(args) => handle_disassemble(mapping, args),
        SubCommandEnum::Stats(args) => handle_stats_report(mapping, args),
        SubCommandEnum::Badge(args) => handle_badge(mapping, args),
    }
}
