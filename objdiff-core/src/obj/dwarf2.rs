use alloc::{borrow::Cow, string::String, vec::Vec};

use anyhow::{Context, Result};
use object::{Object as _, ObjectSection as _};
use typed_arena::Arena;

use crate::obj::{Section, SectionKind};

/// Parse line information from DWARF 2+ sections.
pub(crate) fn parse_line_info_dwarf2(
    obj_file: &object::File,
    sections: &mut [Section],
) -> Result<()> {
    let arena_data = Arena::new();
    let arena_relocations = Arena::new();
    let endian = match obj_file.endianness() {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };
    let dwarf = gimli::Dwarf::load(|id: gimli::SectionId| -> Result<_> {
        load_file_section(id, obj_file, endian, &arena_data, &arena_relocations)
    })
    .context("loading DWARF sections")?;

    let mut iter = dwarf.units();
    if let Some(header) = iter.next().map_err(|e| gimli_error(e, "iterating over DWARF units"))? {
        let unit = dwarf.unit(header).map_err(|e| gimli_error(e, "loading DWARF unit"))?;
        if let Some(program) = unit.line_program.clone() {
            let mut text_sections = sections.iter_mut().filter(|s| s.kind == SectionKind::Code);
            let mut lines = text_sections.next().map(|section| &mut section.line_info);

            let mut rows = program.rows();
            while let Some((header, row)) =
                rows.next_row().map_err(|e| gimli_error(e, "loading program row"))?
            {
                if let (Some(line), Some(lines)) = (row.line(), &mut lines) {
                    // Extract source file name from file index
                    let source_file = extract_source_file(row.file_index(), header);
                    lines.insert(row.address(), (line.get() as u32, source_file));
                }
                if row.end_sequence() {
                    // The next row is the start of a new sequence, which means we must
                    // advance to the next .text section.
                    lines = text_sections.next().map(|section| &mut section.line_info);
                }
            }
        }
    }
    if iter.next().map_err(|e| gimli_error(e, "checking for next unit"))?.is_some() {
        log::warn!("Multiple units found in DWARF data, only processing the first");
    }

    Ok(())
}

/// Extract source file path from a file index and line program header.
fn extract_source_file<R: gimli::Reader>(
    file_index: u64,
    header: &gimli::LineProgramHeader<R, R::Offset>,
) -> String {
    let file_entry = match header.file(file_index) {
        Some(entry) => entry,
        None => return String::new(),
    };
    extract_file_path(file_entry, header).unwrap_or_default()
}

#[derive(Debug, Default)]
struct RelocationMap(object::read::RelocationMap);

impl RelocationMap {
    fn add(&mut self, file: &object::File, section: &object::Section) {
        for (offset, relocation) in section.relocations() {
            if let Err(e) = self.0.add(file, offset, relocation) {
                log::error!(
                    "Relocation error for section {} at offset 0x{:08x}: {}",
                    section.name().unwrap(),
                    offset,
                    e
                );
            }
        }
    }
}

impl gimli::read::Relocate for &'_ RelocationMap {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.0.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        <usize as gimli::ReaderOffset>::from_u64(self.0.relocate(offset as u64, value as u64))
    }
}

type Relocate<'a, R> = gimli::RelocateReader<R, &'a RelocationMap>;

fn load_file_section<'input, 'arena, Endian: gimli::Endianity>(
    id: gimli::SectionId,
    file: &object::File<'input>,
    endian: Endian,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
    arena_relocations: &'arena Arena<RelocationMap>,
) -> Result<Relocate<'arena, gimli::EndianSlice<'arena, Endian>>> {
    let mut relocations = RelocationMap::default();
    let data = match file.section_by_name(id.name()) {
        Some(ref section) => {
            relocations.add(file, section);
            section.uncompressed_data()?
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Cow::Owned(Vec::with_capacity(1)),
    };
    let data_ref = arena_data.alloc(data);
    let section = gimli::EndianSlice::new(data_ref, endian);
    let relocations = arena_relocations.alloc(relocations);
    Ok(Relocate::new(section, relocations))
}

/// Extract file path from DWARF file entry, combining directory and filename.
fn extract_file_path<R: gimli::Reader>(
    file_entry: &gimli::FileEntry<R, R::Offset>,
    header: &gimli::LineProgramHeader<R, R::Offset>,
) -> Result<String> {
    let mut path = String::new();

    // Get the directory if present
    if let Some(dir) = file_entry.directory(header)
        && let Some(dir_str) = attr_value_to_string(dir)
        && !dir_str.is_empty()
    {
        path.push_str(&dir_str);
        // Add separator if needed (handle both Unix and Windows paths)
        if !path.ends_with('/') && !path.ends_with('\\') {
            path.push('/');
        }
    }

    // Get the filename
    if let Some(file_name) = attr_value_to_string(file_entry.path_name()) {
        path.push_str(&file_name);
    }

    Ok(path)
}

/// Convert an AttributeValue to a string if possible.
fn attr_value_to_string<R: gimli::Reader>(value: gimli::AttributeValue<R>) -> Option<String> {
    match value {
        gimli::AttributeValue::String(s) => s.to_string_lossy().ok().map(|s| s.into_owned()),
        gimli::AttributeValue::DebugStrRef(_) => {
            // Would need dwarf context to resolve, skip for now
            None
        }
        gimli::AttributeValue::DebugLineStrRef(_) => {
            // Would need dwarf context to resolve, skip for now
            None
        }
        _ => None,
    }
}

#[inline]
fn gimli_error(e: gimli::Error, context: &str) -> anyhow::Error {
    anyhow::anyhow!("gimli error {context}: {e:?}")
}
