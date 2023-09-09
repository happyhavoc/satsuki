//! Satsuki
//!
//! Simple binary comparison helper tool for Touhou 06.

use std::collections::hash_map::Iter;
use std::fmt::Write;
use std::{collections::HashMap, error::Error};

use capstone::arch::x86::{X86Operand, X86OperandType};
use capstone::arch::ArchOperand;
use capstone::{Capstone, Insn};
use object::{File, Object, ObjectSection, ObjectSymbol, SymbolKind};
use pdb::{FallibleIterator, ProcedureSymbol, PublicSymbol, Source, SymbolData, PDB};
use serde::Deserialize;

#[derive(Debug)]
pub enum ExecutableError {
    ObjectError { error: object::Error },
    PdbError { error: pdb::Error },
    CapstoneError { error: capstone::Error },
    WriteError { error: std::fmt::Error },
    FunctionNameConflict { function_name: String },
}

impl std::fmt::Display for ExecutableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutableError::FunctionNameConflict { function_name } => {
                write!(f, "Function \"{function_name}\" already exist!")
            }
            _ => std::fmt::Debug::fmt(self, f),
        }
    }
}

impl Error for ExecutableError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ExecutableError::ObjectError { error } => Some(error),
            ExecutableError::PdbError { error } => Some(error),
            ExecutableError::WriteError { error } => Some(error),
            _ => None,
        }
    }
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

#[derive(Clone, Debug, Deserialize)]
pub struct FunctionDef {
    pub name: Option<String>,
    pub address: usize,
    pub size: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Mapping {
    pub function: Option<Vec<FunctionDef>>,
}

impl Mapping {
    pub fn get_function_def(&self, name: &str) -> Option<&FunctionDef> {
        if let Some(function) = &self.function {
            for f in function {
                if let Some(f_name) = &f.name {
                    if f_name == name {
                        return Some(f);
                    }
                }
            }
        }

        None
    }
}

/// Represent some executable
#[derive(Clone, Default, Debug)]
pub struct Executable {
    functions: HashMap<String, Function>,
}

impl Executable {
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

    pub fn functions_count(&self) -> usize {
        self.functions.len()
    }

    pub fn functions_iter(&self) -> Iter<'_, String, Function> {
        self.functions.iter()
    }

    pub fn get_function(&self, name: &String) -> Option<&Function> {
        self.functions.get(name)
    }

    pub fn get_function_by_address(&self, address: usize) -> Option<&Function> {
        self.functions
            .values()
            .find(|&function| function.address == address)
    }

    pub fn get_function_stat(&self, other: &Self, name: &String) -> Option<f32> {
        match (self.get_function(name), other.get_function(name)) {
            (Some(a), Some(b)) => Some(a.compute_raw_diff(b)),
            _ => None,
        }
    }

    pub fn generate_stats(&self, other: &Self) -> HashMap<String, Option<f32>> {
        let mut res = HashMap::new();

        for function_name in self.functions.keys() {
            res.insert(
                function_name.clone(),
                self.get_function_stat(other, function_name),
            );
        }

        res
    }

    pub fn from_object(raw_obj: &File) -> Result<Self, ExecutableError> {
        let mut res: Executable = Self::default();

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

    fn add_function_from_pdb(
        &mut self,
        text_section_address: usize,
        text_data: &[u8],
        name: String,
        offset: usize,
        len: usize,
    ) -> Result<(), ExecutableError> {
        if len == 0 {
            return Ok(());
        }

        let data = text_data[offset..offset + len].to_vec();

        match self.add_function(name, text_section_address + offset, data) {
            Ok(()) | Err(ExecutableError::FunctionNameConflict { .. }) => {}
            Err(err) => return Err(err),
        }

        Ok(())
    }

    pub fn from_object_with_pdb<'s, S>(
        raw_obj: &File,
        mapping: Mapping,
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
                        if let Ok(SymbolData::Procedure(ProcedureSymbol {
                            name,
                            offset,
                            len,
                            ..
                        })) = symbol.parse()
                        {
                            let name = name.to_string();
                            let offset = offset.offset as usize;
                            let len = len as usize;

                            res.add_function_from_pdb(
                                text_section_address,
                                text_data,
                                name.into(),
                                offset,
                                len,
                            )?;
                        }
                    }
                }
            }

            let symbol_table = pdb_file.global_symbols()?;

            let mut symbols = symbol_table.iter();
            while let Some(symbol) = symbols.next()? {
                if let Ok(pdb::SymbolData::Public(PublicSymbol {
                    function: true,
                    offset,
                    name,
                    ..
                })) = symbol.parse()
                {
                    let name = name.to_string();
                    let offset = offset.offset as usize;
                    let len = mapping.get_function_def(&name).map(|x| x.size).unwrap_or(0);
                    res.add_function_from_pdb(
                        text_section_address,
                        text_data,
                        name.into(),
                        offset,
                        len,
                    )?;
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

                        match res.add_function(name, function.address, data) {
                            Ok(()) | Err(ExecutableError::FunctionNameConflict { .. }) => {}
                            Err(err) => return Err(err),
                        }
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
    fn format_instruction(
        &self,
        ctx: &Capstone,
        executable: &Executable,
        force_address_zero: bool,
        resolve_names: bool,
        instruction: &Insn<'_>,
    ) -> Result<String, ExecutableError> {
        let mut res = String::new();
        let detail = ctx.insn_detail(instruction)?;
        let arch_detail = detail.arch_detail();
        let groups = detail.groups();
        let mut group_names = Vec::new();

        for group in groups {
            let group_name = ctx.group_name(*group).expect("Cannot grab group name!");

            group_names.push(group_name);
        }

        let mut has_custom_format = false;

        if resolve_names {
            // Handle relative call
            if group_names.contains(&"call".into())
                && group_names.contains(&"branch_relative".into())
            {
                let ops = arch_detail.operands();

                if ops.len() == 1 {
                    if let ArchOperand::X86Operand(X86Operand {
                        op_type: X86OperandType::Imm(immediate),
                        ..
                    }) = ops[0]
                    {
                        let is_32bit = !group_names.contains(&"not64bitmode".into());
                        let target_address = if force_address_zero {
                            if is_32bit {
                                (self.address as i32 + immediate as i32) as usize

                            } else {
                                (self.address as i64 + immediate) as usize
                            }
                        } else {
                            immediate as usize
                        };

                        if let Some(target_function) = executable.get_function_by_address(target_address)
                        {
                            if let Some(mnemonic) = instruction.mnemonic() {
                                writeln!(res, "{} {}", mnemonic, target_function.name)?;

                                has_custom_format = true;
                            }
                        }
                    }
                }
            }
        }

        if !has_custom_format {
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

    pub fn disassemble(
        &self,
        ctx: &Capstone,
        executable: &Executable,
        force_address_zero: bool,
        resolve_names: bool,
    ) -> Result<String, ExecutableError> {
        let address = if force_address_zero {
            0
        } else {
            self.address as u64
        };

        let instructions = ctx.disasm_all(&self.data, address)?;

        let mut res = String::new();

        for instruction in instructions.iter() {
            res.push_str(&self.format_instruction(
                ctx,
                executable,
                force_address_zero,
                resolve_names,
                instruction,
            )?);
        }

        Ok(res)
    }

    pub fn compute_raw_diff(&self, other: &Function) -> f32 {
        let expected_function_size = self.data.len();
        let mut matching_count = 0;

        for (idx, a) in self.data.iter().enumerate() {
            if let Some(b) = other.data.get(idx) {
                if a == b {
                    matching_count += 1;
                }
            }
        }

        let result = (matching_count as f32 / expected_function_size as f32) * 100.0;

        assert!(result != 100.0 || expected_function_size == other.data.len());

        result
    }
}
