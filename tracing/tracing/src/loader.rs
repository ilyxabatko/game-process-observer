use crate::util::elf::{ElfError, ElfInfo, SymbolInfo};
use aya::{
    Btf, Ebpf,
    programs::{
        Program as AyaProgram, ProgramError, kprobe::KProbeLinkId, lsm::LsmLinkId,
        trace_point::TracePointLinkId,
    },
};
use std::collections::HashMap;
use thiserror::Error;

pub struct Programs<'a> {
    map: HashMap<String, Program<'a>>,
}

impl<'a> Programs<'a> {
    pub fn with_ebpf(ebpf: &'a mut Ebpf) -> Self {
        let map = ebpf
            .programs_mut()
            .map(|(name, prog)| {
                let name_str = name.to_string();
                let program = Program::from_program(name_str.clone(), prog);
                (name_str, program)
            })
            .collect();

        Self { map }
    }

    pub fn with_elf_info(mut self, data: &[u8]) -> Result<Self, ElfError> {
        let elf_info = ElfInfo::from_raw_elf(data)?;

        // program_name is an Elf symbol name
        for (program_name, program) in self.map.iter_mut() {
            if let Some(symbol_info) = elf_info.get_by_symbol_name(program_name) {
                program.with_sym_info(symbol_info.clone());
            }
        }

        Ok(self)
    }
}

#[derive(Debug)]
pub struct Program<'a> {
    pub program_name: String,
    pub program: &'a mut AyaProgram,
    pub attach_point: Option<String>,
    pub info: Option<SymbolInfo>,
    pub enabled: bool,
    pub loaded: bool,
    pub attached: bool,
    pub link_id: Option<LoadedLink>,
}

#[derive(Debug)]
pub enum LoadedLink {
    KProbe(KProbeLinkId),
    TracePoint(TracePointLinkId),
    Lsm(LsmLinkId),
}

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("program not found: {0}")]
    ProgramNotFound(String),

    #[error("attach point missing for {0}")]
    AttachPointMissing(String),

    #[error("tracepoint category missing for {0}")]
    TracePointCategoryMissing(String),

    #[error("Program '{0}' is disabled")]
    ProgramIsDisabled(String),

    #[error("aya program error: {0}")]
    Aya(#[from] ProgramError),
}

impl<'a> Program<'a> {
    pub fn from_program(name: String, program: &'a mut AyaProgram) -> Self {
        Self {
            program_name: name,
            program,
            attach_point: None,
            info: None,
            enabled: false,
            loaded: false,
            attached: false,
            link_id: None,
        }
    }

    pub fn with_sym_info(&mut self, info: SymbolInfo) -> &mut Self {
        self.info = Some(info);

        self.attach_point = self.info.as_ref().and_then(|info| {
            info.section_name
                .split('/')
                .next_back()
                .map(|s| s.to_string())
        });

        self
    }

    #[inline]
    fn tracepoint_category(&self) -> Option<String> {
        self.info.as_ref().and_then(|info| {
            let v: Vec<&str> = info.section_name.split('/').collect();
            v.get(v.len() - 2).map(|s| s.to_string())
        })
    }

    pub fn load(&mut self, btf: &Btf) -> Result<(), LoaderError> {
        if !self.enabled {
            return Err(LoaderError::ProgramIsDisabled(self.program_name.clone()));
        }

        let hook = self
            .attach_point
            .clone()
            .ok_or(LoaderError::AttachPointMissing(self.program_name.clone()))?;

        match self.program {
            AyaProgram::TracePoint(tracepoint) => {
                tracepoint.load()?;
            }
            AyaProgram::KProbe(kprobe) => {
                kprobe.load()?;
            }
            AyaProgram::Lsm(lsm) => {
                lsm.load(&hook, btf)?;
            }
            _ => unimplemented!(),
        }

        self.loaded = true;
        Ok(())
    }

    pub fn unload(&mut self) -> Result<(), LoaderError> {
        match self.program {
            AyaProgram::TracePoint(tracepoint) => {
                tracepoint.unload()?;
            }
            AyaProgram::KProbe(kprobe) => {
                kprobe.unload()?;
            }
            AyaProgram::Lsm(lsm) => {
                lsm.unload()?;
            }
            _ => unimplemented!(),
        }

        self.loaded = false;
        self.attached = false;

        Ok(())
    }

    pub fn attach(&mut self) -> Result<(), LoaderError> {
        let program_name = self.program_name.clone();
        let attach_function = self.attach_point.clone();
        let tracepoint_category = self.tracepoint_category();

        match self.program {
            AyaProgram::TracePoint(tracepoint) => {
                let tracepoint_category = tracepoint_category
                    .ok_or(LoaderError::TracePointCategoryMissing(program_name.clone()))?;
                let attach_function =
                    attach_function.ok_or(LoaderError::AttachPointMissing(program_name))?;

                self.link_id = Some(LoadedLink::TracePoint(
                    tracepoint.attach(&tracepoint_category, &attach_function)?,
                ));
            }
            AyaProgram::KProbe(kprobe) => {
                let attach_function =
                    attach_function.ok_or(LoaderError::AttachPointMissing(program_name))?;

                self.link_id = Some(LoadedLink::KProbe(kprobe.attach(&attach_function, 0)?));
            }
            AyaProgram::Lsm(lsm) => {
                self.link_id = Some(LoadedLink::Lsm(lsm.attach()?));
            }
            _ => unimplemented!(),
        }

        self.attached = true;
        Ok(())
    }
}
