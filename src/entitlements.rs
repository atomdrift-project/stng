//! Mach-O entitlements extraction from code signatures.

use crate::types::{ExtractedString, StringKind, StringMethod};
use goblin::mach::MachO;

/// Extract entitlements from Mach-O code signature as raw XML.
///
/// Returns the full XML plist as a single string for inline display.
pub fn extract_macho_entitlements(
    macho: &MachO<'_>,
    data: &[u8],
    _min_length: usize,
) -> Vec<ExtractedString> {
    use goblin::mach::load_command::CommandVariant;

    let mut entitlements = Vec::new();

    // Find LC_CODE_SIGNATURE load command
    for cmd in &macho.load_commands {
        if let CommandVariant::CodeSignature(ref cs) = cmd.command {
            let offset = cs.dataoff as usize;
            let size = cs.datasize as usize;

            if offset + size > data.len() {
                continue;
            }

            let cs_data = &data[offset..offset + size];

            // Look for XML plist (starts with <?xml)
            if let Some(xml_start) = cs_data.windows(5).position(|w| w == b"<?xml") {
                let xml_data = &cs_data[xml_start..];

                // Find end of plist
                if let Some(plist_end) = xml_data.windows(8).position(|w| w == b"</plist>") {
                    let xml_content = &xml_data[..plist_end + 8]; // include </plist>

                    if let Ok(xml_str) = String::from_utf8(xml_content.to_vec()) {
                        entitlements.push(ExtractedString {
                            value: xml_str,
                            data_offset: (offset + xml_start) as u64,
                            section: Some("__LINKEDIT".to_string()),
                            method: StringMethod::CodeSignature,
                            kind: StringKind::EntitlementsXml,
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    entitlements
}
