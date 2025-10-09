use object::{self, Object, ObjectSection, ObjectSymbol};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ElfError {
    #[error("object error: {0}")]
    Object(#[from] object::Error),
}

#[derive(Debug, Default)]
pub struct ElfInfo {
    symbols: HashMap<String, SymbolInfo>,
}

#[derive(Debug, Default, Clone)]
pub struct SymbolInfo {
    pub section_name: String,
}

impl ElfInfo {
    pub fn from_raw_elf(data: &[u8]) -> Result<Self, ElfError> {
        let object = object::read::File::parse(data)?;
        let mut info: Self = Default::default();

        for symbol in object.symbols() {
            if let Some(section) = symbol
                .section_index()
                .and_then(|i| object.section_by_index(i).ok())
                && let (Ok(symbol_name), Ok(section_name)) = (symbol.name(), section.name())
            {
                info.symbols.insert(
                    symbol_name.to_string(),
                    SymbolInfo {
                        section_name: section_name.to_string(),
                    },
                );
            }
        }
        Ok(info)
    }

    pub fn get_by_symbol_name<S: AsRef<str>>(&self, symbol_name: S) -> Option<&SymbolInfo> {
        self.symbols.get(symbol_name.as_ref())
    }
}
