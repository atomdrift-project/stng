//! Mach-O entitlements extraction from code signatures.

use crate::types::{ExtractedString, StringKind, StringMethod};
use goblin::mach::MachO;

/// The XML entitlements in a Mach-O's code signature.
///
/// Read from the signature's entitlements slot: a code signature also embeds
/// other plists (the CMS `cdhashes` attribute), so the first `<?xml` in the
/// blob is not necessarily the entitlements.
pub(crate) fn extract_macho_entitlements(macho: &MachO<'_>, data: &[u8]) -> Vec<ExtractedString> {
    use goblin::mach::load_command::CommandVariant;

    macho
        .load_commands
        .iter()
        .filter_map(|cmd| match cmd.command {
            CommandVariant::CodeSignature(ref cs) => Some(cs),
            _ => None,
        })
        .filter_map(|cs| {
            let blob =
                crate::binary::file_range(data, u64::from(cs.dataoff), u64::from(cs.datasize))?;
            let (at, xml) = entitlements_xml(blob)?;
            Some(ExtractedString {
                value: String::from_utf8(xml.to_vec()).ok()?,
                data_offset: u64::from(cs.dataoff) + at as u64,
                method: StringMethod::CodeSignature,
                kind: Some(StringKind::EntitlementsXml),
                ..Default::default()
            })
        })
        .collect()
}

/// The entitlements plist in a code-signature SuperBlob, with its offset in
/// the blob. Big-endian: `magic, length, count`, then `count` index entries
/// of `(slot type, offset)`; slot 5 holds a `0xfade7171` blob whose payload
/// is the XML.
fn entitlements_xml(blob: &[u8]) -> Option<(usize, &[u8])> {
    const SUPERBLOB: u32 = 0xfade_0cc0;
    const ENTITLEMENTS_SLOT: u32 = 5;
    const ENTITLEMENTS: u32 = 0xfade_7171;
    let be32 = |at: usize| crate::bytes::u32_be(blob, at);
    if be32(0)? != SUPERBLOB {
        return None;
    }
    let count = usize::try_from(be32(8)?).ok()?;
    let index = (0..count.min(blob.len() / 8)).find_map(|i| {
        let entry = 12usize.checked_add(i.checked_mul(8)?)?;
        (be32(entry)? == ENTITLEMENTS_SLOT)
            .then(|| be32(entry + 4))
            .flatten()
    })?;
    let start = usize::try_from(index).ok()?;
    if be32(start)? != ENTITLEMENTS {
        return None;
    }
    let len = usize::try_from(be32(start.checked_add(4)?)?).ok()?;
    let payload = blob.get(start.checked_add(8)?..start.checked_add(len)?)?;
    let xml_start = memchr::memmem::find(payload, b"<?xml")?;
    let xml = &payload[xml_start..];
    let end = memchr::memmem::find(xml, b"</plist>")? + b"</plist>".len();
    Some((start + 8 + xml_start, &xml[..end]))
}
