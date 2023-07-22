//! Satsuki
//!
//! Simple binary comparison helper tool for Touhou 06.

use std::collections::HashMap;
use std::fmt::Write;

use capstone::Capstone;
use object::{File, Object, ObjectSection, ObjectSymbol, SymbolKind};
use pdb::{FallibleIterator, ProcedureSymbol, Source, SymbolData, PDB};
use serde::Deserialize;

#[derive(Debug)]
pub enum ExecutableError {
    ObjectError { error: object::Error },
    PdbError { error: pdb::Error },
    CapstoneError { error: capstone::Error },
    WriteError { error: std::fmt::Error },
    FunctionNameConflict { function_name: String },
}

impl From<object::Error> for ExecutableError {
    fn from(error: object::Error) -> Self {
        Self::ObjectError { error }
    }
}

impl From<pdb::Error> for ExecutableError {
    fn from(error: pdb::Error) -> Self {
        Self::PdbError { error }
    }
}

impl From<capstone::Error> for ExecutableError {
    fn from(error: capstone::Error) -> Self {
        Self::CapstoneError { error }
    }
}

impl From<std::fmt::Error> for ExecutableError {
    fn from(error: std::fmt::Error) -> Self {
        Self::WriteError { error }
    }
}

#[derive(Debug, Deserialize)]
pub struct FunctionDef {
    pub name: Option<String>,
    pub address: usize,
    pub size: usize,
}

#[derive(Debug, Deserialize)]
pub struct Mapping {
    pub function: Option<Vec<FunctionDef>>,
}

/// Represent some executable
#[derive(Clone, Debug)]
pub struct Executable {
    functions: HashMap<String, Function>,
}

impl Executable {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    pub fn add_function(
        &mut self,
        name: String,
        address: usize,
        data: Vec<u8>,
    ) -> Result<(), ExecutableError> {
        if self.functions.contains_key(&name) {
            return Err(ExecutableError::FunctionNameConflict {
                function_name: name,
            });
        }

        self.functions.insert(
            name.clone(),
            Function {
                name,
                address,
                data,
            },
        );

        Ok(())
    }

    pub fn get_function(&self, name: &String) -> Option<&Function> {
        self.functions.get(name)
    }

    pub fn from_object(raw_obj: &File) -> Result<Self, ExecutableError> {
        let mut res: Executable = Self::new();

        if let Some(text_sec) = raw_obj.section_by_name(".text") {
            let text_section_address = text_sec.address() as usize;
            let text_data = text_sec.data()?;

            for sym in raw_obj
                .symbols()
                .filter(|x| x.kind() == SymbolKind::Text && x.size() != 0)
            {
                let name = sym.name()?;

                let address = sym.address() as usize;
                let size = sym.size() as usize;
                let offset = address - text_section_address;
                let data = text_data[offset..offset + size].to_vec();

                if size == 0 {
                    continue;
                }

                res.add_function(name.into(), sym.address() as usize, data)?;
            }
        }

        Ok(res)
    }

    pub fn from_object_with_pdb<'s, S>(
        raw_obj: &File,
        mut pdb_file: PDB<'s, S>,
    ) -> Result<Self, ExecutableError>
    where
        S: Source<'s> + 's,
    {
        let mut res = Self::from_object(raw_obj)?;

        if let Some(text_sec) = raw_obj.section_by_name(".text") {
            let text_section_address = text_sec.address() as usize;
            let text_data = text_sec.data()?;

            let dbi = pdb_file.debug_information()?;
            let mut modules = dbi.modules()?;

            while let Some(module) = modules.next()? {
                if let Some(module_info) = pdb_file.module_info(&module)? {
                    let mut iter = module_info.symbols()?;

                    while let Some(symbol) = iter.next()? {
                        match symbol.parse() {
                            Ok(SymbolData::Procedure(ProcedureSymbol {
                                name,
                                offset,
                                len,
                                ..
                            })) => {
                                let name = name.to_string();
                                let offset = offset.offset as usize;
                                let len = len as usize;

                                if len == 0 {
                                    continue;
                                }

                                let data = text_data[offset..offset + len].to_vec();

                                match res.add_function(
                                    name.into(),
                                    text_section_address + offset,
                                    data,
                                ) {
                                    Ok(()) | Err(ExecutableError::FunctionNameConflict { .. }) => {}
                                    Err(err) => return Err(err),
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(res)
    }

    pub fn from_object_with_mapping(
        raw_obj: &File,
        mapping: Mapping,
    ) -> Result<Self, ExecutableError> {
        let mut res = Self::from_object(raw_obj)?;

        if let Some(text_sec) = raw_obj.section_by_name(".text") {
            let text_section_address = text_sec.address() as usize;
            let text_data = text_sec.data()?;

            if let Some(functions) = mapping.function {
                for function in functions {
                    if let Some(name) = function.name {
                        let offset = function.address - text_section_address;
                        let data = text_data[offset..offset + function.size].to_vec();

                        res.add_function(name, function.address, data)?;
                    }
                }
            }
        }

        Ok(res)
    }
}

#[derive(Clone, Debug)]
pub struct Function {
    pub name: String,
    pub address: usize,
    pub data: Vec<u8>,
}

impl Function {
    pub fn disassemble(
        &self,
        ctx: &Capstone,
        force_address_zero: bool,
    ) -> Result<String, ExecutableError> {
        let address = if force_address_zero {
            0
        } else {
            self.address as u64
        };

        let instructions = ctx.disasm_all(&self.data, address)?;

        let mut res = String::new();

        for instruction in instructions.iter() {
            if let Some(mnemonic) = instruction.mnemonic() {
                write!(res, "{} ", mnemonic)?;
                if let Some(op_str) = instruction.op_str() {
                    write!(res, "{}", op_str)?;
                }

                res.push('\n');
            }
        }

        Ok(res)
    }
}
