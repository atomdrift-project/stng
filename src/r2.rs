//! Optional rizin/radare2 integration for smarter string extraction.
//!
//! Prefers rizin when available, falls back to radare2.
//! Provides better differentiation between true strings and symbols.

pub mod cache;

use crate::go::classify_string;
use crate::{ExtractedString, FunctionMetadata, StringKind, StringMethod};
use cache::R2Cache;
use std::collections::HashSet;
use std::process::Command;
use std::sync::OnceLock;

/// Which tool is available (cached after first check)
static TOOL: OnceLock<Option<&'static str>> = OnceLock::new();

/// Check if rizin or radare2 is available, preferring rizin.
pub fn is_available() -> bool {
    get_tool().is_some()
}

/// Flush cached r2 results for a specific file.
pub fn flush_cache(file_path: &str) -> Result<(), std::io::Error> {
    let cache = R2Cache::new()?;
    cache.clear(file_path)
}

/// Get the available tool name (rizin preferred, then radare2)
fn get_tool() -> Option<&'static str> {
    *TOOL.get_or_init(|| {
        if Command::new("rizin")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            Some("rizin")
        } else if Command::new("r2")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            Some("r2")
        } else {
            None
        }
    })
}

/// Extract string boundaries from radare2/rizin.
/// Returns offset and length of each string found by r2.
/// These can be used as hints for XOR string extraction.
///
/// Uses `izzj` (whole binary scan) for files ≤10MB.
/// For large files (>10MB), returns None to avoid slow scan.
pub fn extract_string_boundaries(path: &str) -> Option<Vec<StringBoundary>> {
    let tool = get_tool()?;

    // Check file size - skip for large files (izzj is too slow)
    let file_size = std::fs::metadata(path).ok()?.len();
    if file_size > 10 * 1024 * 1024 {
        tracing::debug!(
            "r2::extract_string_boundaries: skipping large file ({}MB)",
            file_size / 1024 / 1024
        );
        return None;
    }

    tracing::debug!("r2::extract_string_boundaries: extracting from {}", path);

    // Use izzj for whole binary scan (better than izj for data sections only)
    let data_strings = run_tool_command(tool, path, "izzj")?;

    if let Ok(json) = serde_json::from_str::<Vec<R2String>>(&data_strings) {
        let boundaries: Vec<StringBoundary> = json
            .iter()
            .map(|s| StringBoundary {
                offset: s.paddr,
                length: if s.length > 0 {
                    s.length
                } else {
                    s.string.len()
                },
            })
            .collect();

        tracing::debug!(
            "r2::extract_string_boundaries: found {} string boundaries",
            boundaries.len()
        );

        Some(boundaries)
    } else {
        tracing::debug!("r2::extract_string_boundaries: failed to parse JSON");
        None
    }
}

/// Extract strings using rizin or radare2.
///
/// Uses `izz` (whole binary scan) for strings and `is` for symbols.
/// For large files (>10MB), only extracts symbols/imports (fast mode) to avoid
/// the very slow whole-binary string scan.
/// Returns strings with R2String/R2Symbol methods for clear identification.
pub fn extract_strings(
    path: &str,
    min_length: usize,
    use_cache: bool,
) -> Option<Vec<ExtractedString>> {
    let tool = get_tool()?;

    // Get file size to filter out symbols with invalid offsets
    let file_size = std::fs::metadata(path).ok()?.len();
    let is_large_file = file_size > 10 * 1024 * 1024; // >10MB

    tracing::debug!(
        "r2::extract_strings: file_size={} (0x{:x}), large_file={}",
        file_size,
        file_size,
        is_large_file
    );

    // For large files: only extract symbols (fast), skip slow string scan
    // For small files: extract both strings and symbols
    let path_owned = path.to_string();
    let (data_result, symbols_result) = if is_large_file {
        tracing::debug!(
            "r2::extract_strings: large file, skipping izzj scan (slow), using symbols only"
        );
        (
            None,
            run_tool_command_with_cache(tool, &path_owned, "isj", use_cache),
        )
    } else {
        rayon::join(
            || run_tool_command_with_cache(tool, &path_owned, "izzj", use_cache),
            || run_tool_command_with_cache(tool, &path_owned, "isj", use_cache),
        )
    };

    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Process strings from all sections (whole binary scan)
    if let Some(data_strings) = data_result {
        tracing::debug!("r2::extract_strings: got izzj output, parsing JSON...");
        if let Ok(json) = serde_json::from_str::<Vec<R2String>>(&data_strings) {
            tracing::debug!(
                "r2::extract_strings: parsed {} strings from izzj",
                json.len()
            );
            for s in json {
                // Skip strings with invalid file offsets
                if s.paddr > file_size {
                    tracing::debug!(
                        "r2::extract_strings: SKIP paddr {} > file_size {} for '{}'",
                        s.paddr,
                        file_size,
                        if s.string.len() > 20 {
                            &s.string[..20]
                        } else {
                            &s.string
                        }
                    );
                    continue;
                }

                // Check if it's our target XOR key
                if s.string.contains("fYzt") {
                    tracing::debug!("r2::extract_strings: FOUND XOR KEY: paddr=0x{:x}, len={}, section='{}', string='{}'",
                        s.paddr, s.string.len(), s.section, s.string);
                }

                if s.string.len() >= min_length && seen.insert(s.string.clone()) {
                    let kind = classify_string(&s.string);
                    strings.push(ExtractedString {
                        value: s.string,
                        data_offset: s.paddr,
                        section: Some(s.section),
                        method: StringMethod::R2String,
                        kind,
                        ..Default::default()
                    });
                } else if s.string.contains("fYzt") {
                    tracing::debug!("r2::extract_strings: XOR KEY FILTERED: len={} < min_length={}, or already seen",
                        s.string.len(), min_length);
                }
            }
        }
    }
    tracing::debug!(
        "r2::extract_strings: collected {} strings from izj",
        strings.len()
    );

    // Extract function metadata (for files < 2MB)
    let function_metadata = extract_function_metadata(path, file_size, use_cache);

    // Process symbols
    if let Some(symbols) = symbols_result {
        if let Ok(json) = serde_json::from_str::<Vec<R2Symbol>>(&symbols) {
            for s in json {
                // Skip symbols with invalid file offsets
                if s.paddr > file_size {
                    continue;
                }
                if s.name.len() >= min_length && seen.insert(s.name.clone()) {
                    let kind = classify_r2_symbol(&s.r#type, &s.bind);

                    // Look up function metadata if this is a function
                    let func_meta = if s.r#type == "FUNC" || s.r#type == "METH" {
                        function_metadata.as_ref().and_then(
                            |map: &std::collections::HashMap<String, FunctionMetadata>| {
                                // Try exact match first
                                map.get(&s.name)
                                    .cloned()
                                    // Try without sym. prefix
                                    .or_else(|| {
                                        let clean_name = s
                                            .name
                                            .strip_prefix("sym.")
                                            .or_else(|| s.name.strip_prefix("sym.imp."))
                                            .unwrap_or(&s.name);
                                        map.get(clean_name).cloned()
                                    })
                            },
                        )
                    } else {
                        None
                    };

                    strings.push(ExtractedString {
                        value: s.name,
                        data_offset: s.paddr,
                        section: s.section,
                        method: StringMethod::R2Symbol,
                        kind,
                        library: None,
                        fragments: None,
                        section_size: None,
                        section_executable: None,
                        section_writable: None,
                        architecture: None,
                        function_meta: func_meta,
                    });
                }
            }
        }
    }

    if strings.is_empty() {
        None
    } else {
        Some(strings)
    }
}

/// Extract function metadata using radare2/rizin analysis.
/// Only runs for files < 2MB to avoid performance issues.
/// Returns HashMap of function name -> metadata.
pub fn extract_function_metadata(
    path: &str,
    file_size: u64,
    use_cache: bool,
) -> Option<std::collections::HashMap<String, FunctionMetadata>> {
    // Only analyze functions for files < 2MB
    if file_size > 2 * 1024 * 1024 {
        tracing::debug!(
            "r2::extract_function_metadata: skipping large file ({}MB)",
            file_size / 1024 / 1024
        );
        return None;
    }

    let tool = get_tool()?;

    tracing::debug!(
        "r2::extract_function_metadata: analyzing functions for {}",
        path
    );

    // Run analysis and get function list as JSON
    // aaa = analyze all, aflj = list functions as JSON
    let functions_json = run_tool_command_with_cache(tool, path, "aaa; aflj", use_cache)?;

    #[derive(serde::Deserialize)]
    struct R2Function {
        name: String,
        #[serde(default)]
        size: u64,
        #[serde(default)]
        nbbs: u64, // number of basic blocks
        #[serde(default)]
        edges: u64, // number of branches
        #[serde(default)]
        ninstrs: u64, // number of instructions
        #[serde(default)]
        signature: Option<String>,
        #[serde(default)]
        noreturn: bool,
    }

    let functions: Vec<R2Function> = serde_json::from_str(&functions_json).ok()?;

    let mut metadata_map = std::collections::HashMap::new();
    for func in functions {
        // Clean up function name (remove sym. prefix if present)
        let clean_name = func
            .name
            .strip_prefix("sym.")
            .or_else(|| func.name.strip_prefix("sym.imp."))
            .unwrap_or(&func.name)
            .to_string();

        metadata_map.insert(
            clean_name,
            FunctionMetadata {
                size: func.size,
                basic_blocks: func.nbbs,
                branches: func.edges,
                instructions: func.ninstrs,
                signature: func.signature,
                noreturn: if func.noreturn { Some(true) } else { None },
            },
        );
    }

    tracing::debug!(
        "r2::extract_function_metadata: extracted metadata for {} functions",
        metadata_map.len()
    );

    Some(metadata_map)
}

fn run_tool_command(tool: &str, path: &str, cmd: &str) -> Option<String> {
    run_tool_command_with_cache(tool, path, cmd, true)
}

fn run_tool_command_with_cache(
    tool: &str,
    path: &str,
    cmd: &str,
    use_cache: bool,
) -> Option<String> {
    // Try cache first if enabled
    if use_cache {
        if let Ok(cache) = R2Cache::new() {
            if let Some(cached) = cache.get(path, cmd) {
                return Some(cached);
            }
        }
    }

    // Cache miss or disabled - run command
    let output = Command::new(tool)
        .args(["-q", "-c", cmd, path])
        .output()
        .ok()?;

    if output.status.success() {
        let result = String::from_utf8(output.stdout).ok()?;

        // Store in cache for next time
        if use_cache {
            if let Ok(cache) = R2Cache::new() {
                let _ = cache.set(path, cmd, &result);
            }
        }

        Some(result)
    } else {
        None
    }
}

#[derive(serde::Deserialize, Clone)]
struct R2String {
    paddr: u64,
    string: String,
    section: String,
    #[serde(default)]
    length: usize,
}

/// String boundary hint from radare2
#[derive(Debug, Clone)]
pub struct StringBoundary {
    pub offset: u64,
    pub length: usize,
}

#[derive(serde::Deserialize)]
struct R2Symbol {
    paddr: u64,
    name: String,
    #[serde(default)]
    section: Option<String>,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    bind: String,
}

fn classify_r2_symbol(type_str: &str, bind: &str) -> StringKind {
    match type_str {
        "FUNC" | "METH" => StringKind::FuncName,
        "FILE" => StringKind::FilePath,
        "OBJECT" if bind == "GLOBAL" => StringKind::Ident,
        _ => StringKind::Ident,
    }
}

/// Confidence level for XOR key detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XorConfidence {
    High,   // Verified XOR loop pattern in disassembly
    Medium, // Referenced in executable code
    Low,    // String characteristics suggest XOR key
}

/// Information about a detected XOR key
#[derive(Debug, Clone)]
pub struct XorKeyInfo {
    pub key: String,
    pub confidence: XorConfidence,
    pub reference_count: usize,
    pub offset: u64,
}

/// Analyze candidates by XOR loop patterns without requiring xrefs.
/// Used as a fallback when reference-based filtering finds too few candidates.
fn analyze_candidates_by_patterns(
    tool: &str,
    path: &str,
    candidates: &[&ExtractedString],
) -> Vec<XorKeyInfo> {
    tracing::debug!(
        "analyze_candidates_by_patterns: analyzing {} candidates",
        candidates.len()
    );

    // Get all function names (run aaa first to ensure analysis is done)
    let functions_cmd = "aaa; afl";
    let Some(functions) = run_tool_command(tool, path, functions_cmd) else {
        tracing::debug!("analyze_candidates_by_patterns: failed to get function list");
        return vec![];
    };

    let function_lines: Vec<&str> = functions.lines().collect();
    tracing::debug!(
        "analyze_candidates_by_patterns: found {} functions",
        function_lines.len()
    );
    if function_lines.is_empty() {
        tracing::debug!(
            "analyze_candidates_by_patterns: functions output length: {} bytes",
            functions.len()
        );
        tracing::debug!(
            "analyze_candidates_by_patterns: functions output preview: '{}'",
            if functions.len() > 100 {
                &functions[..100]
            } else {
                &functions
            }
        );
    } else {
        tracing::debug!(
            "analyze_candidates_by_patterns: first function line: '{}'",
            function_lines[0]
        );
    }

    let mut results = vec![];
    let mut xor_func_count = 0;

    // Check first 300 functions for XOR loops (more thorough search)
    let max_funcs = 300.min(function_lines.len());

    // Build a single compound command to disassemble all functions at once
    // This avoids running 'aaa' 300 times which is prohibitively slow
    let mut cmd_parts = vec!["aaa".to_string(), "e scr.color=0".to_string()];
    let mut func_addrs = vec![];

    for func_line in function_lines.iter().take(max_funcs) {
        let parts: Vec<&str> = func_line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let func_addr = parts[0];
        func_addrs.push(func_addr.to_string());
        cmd_parts.push(format!("pdf @ {func_addr}"));
        cmd_parts.push(format!("echo ===FUNC_SEPARATOR_{func_addr}==="));
    }

    let compound_cmd = cmd_parts.join("; ");
    tracing::debug!(
        "analyze_candidates_by_patterns: disassembling {} functions in one session",
        func_addrs.len()
    );

    let Some(all_output) = run_tool_command(tool, path, &compound_cmd) else {
        tracing::debug!(
            "analyze_candidates_by_patterns: failed to run compound disassembly command"
        );
        return vec![];
    };

    // Parse the combined output by splitting on function separators
    // Split by generic separator pattern, then match with function addresses
    let separator_parts: Vec<&str> = all_output.split("===FUNC_SEPARATOR_").collect();

    for (func_idx, func_addr) in func_addrs.iter().enumerate() {
        if func_idx % 50 == 0 && func_idx > 0 {
            tracing::debug!(
                "  analyzed {}/{} functions... ({} with XOR so far)",
                func_idx,
                func_addrs.len(),
                xor_func_count
            );
        }

        // Get the disassembly chunk for this function
        // Index is func_idx because first split is before any separator
        let disasm = if func_idx + 1 < separator_parts.len() {
            // Take the part before this function's separator
            separator_parts[func_idx]
        } else {
            continue;
        };

        // Look for XOR loop patterns
        let has_xor_loop = disasm.contains("eor ") || disasm.contains("xor ");
        if !has_xor_loop {
            continue;
        }

        // Track how many XOR functions we've found
        xor_func_count += 1;
        if xor_func_count <= 5 {
            tracing::debug!(
                "analyze_candidates_by_patterns: function {} (#{}) has XOR instructions",
                func_addr,
                xor_func_count
            );
        }

        // Check if any candidate addresses appear in this XOR function
        for candidate in candidates {
            let addr_str = format!("0x{:x}", candidate.data_offset);

            // Also try virtual address format (add base address)
            let vaddr_str = format!("0x{:x}", candidate.data_offset + 0x100000000);

            if disasm.contains(&addr_str) || disasm.contains(&vaddr_str) {
                tracing::debug!(
                    "analyze_candidates_by_patterns: found candidate '{}' @ {} in XOR function {}",
                    if candidate.value.len() > 20 {
                        &candidate.value[..20]
                    } else {
                        &candidate.value
                    },
                    addr_str,
                    func_addr
                );

                results.push(XorKeyInfo {
                    key: candidate.value.clone(),
                    confidence: XorConfidence::High,
                    reference_count: 1,
                    offset: candidate.data_offset,
                });
            }
        }
    }

    tracing::debug!(
        "analyze_candidates_by_patterns: found {} high-confidence keys",
        results.len()
    );
    results
}

/// Verify if strings are likely used as XOR keys by analyzing their usage.
///
/// This function:
/// 1. Finds cross-references to each string
/// 2. Disassembles functions that reference the string
/// 3. Looks for XOR loop patterns (load byte, XOR, store byte)
/// 4. Returns high-confidence keys for decryption attempts
pub fn verify_xor_keys(path: &str, candidates: &[ExtractedString]) -> Vec<XorKeyInfo> {
    tracing::debug!(
        "verify_xor_keys: called with {} candidates",
        candidates.len()
    );

    let tool = if let Some(t) = get_tool() {
        tracing::debug!("verify_xor_keys: using tool={}", t);
        t
    } else {
        tracing::debug!("verify_xor_keys: no r2/rizin tool found");
        return Vec::new();
    };

    // Check if XOR key is in input candidates
    let xor_key_in_input = candidates.iter().any(|s| s.value.contains("fYzt"));
    tracing::debug!(
        "verify_xor_keys: XOR key in input candidates: {}",
        xor_key_in_input
    );
    if xor_key_in_input {
        if let Some(key_candidate) = candidates.iter().find(|s| s.value.contains("fYzt")) {
            tracing::debug!(
                "verify_xor_keys: XOR key found in input: '{}' @ 0x{:x}, method={:?}",
                key_candidate.value,
                key_candidate.data_offset,
                key_candidate.method
            );
        }
    }

    // Analyze all (analyze all functions) - required for cross-references
    tracing::debug!("verify_xor_keys: running 'aaa' analysis...");
    let _ = run_tool_command(tool, path, "aaa");

    // Filter candidates to reasonable XOR key lengths (8-64 chars)
    let candidates: Vec<_> = candidates
        .iter()
        .filter(|s| s.value.len() >= 8 && s.value.len() <= 64)
        .collect();

    tracing::debug!(
        "verify_xor_keys: {} candidates after length filter (8-64 chars)",
        candidates.len()
    );

    // Check if XOR key survived length filter
    let xor_key_after_filter = candidates.iter().any(|s| s.value.contains("fYzt"));
    tracing::debug!(
        "verify_xor_keys: XOR key after length filter: {}",
        xor_key_after_filter
    );
    for (i, c) in candidates.iter().take(5).enumerate() {
        tracing::debug!(
            "  candidate[{}]: '{}' @ 0x{:x}",
            i,
            if c.value.len() > 20 {
                &c.value[..20]
            } else {
                &c.value
            },
            c.data_offset
        );
    }

    // Pre-filter: count references for each candidate to narrow down the search space
    // Limit to first 200 candidates for performance
    let max_candidates_to_check = 200.min(candidates.len());
    tracing::debug!(
        "verify_xor_keys: counting references for first {} candidates (out of {})...",
        max_candidates_to_check,
        candidates.len()
    );

    let mut candidates_with_refs: Vec<_> = Vec::new();
    for (i, candidate) in candidates.iter().take(max_candidates_to_check).enumerate() {
        if i % 50 == 0 && i > 0 {
            tracing::debug!(
                "  processed {}/{} candidates...",
                i,
                max_candidates_to_check
            );
        }

        let vaddr = candidate.data_offset;
        let xrefs_cmd = format!("axt 0x{vaddr:x}");
        let Some(xrefs) = run_tool_command(tool, path, &xrefs_cmd) else {
            continue;
        };
        let xref_lines: Vec<String> = xrefs
            .lines()
            .map(std::string::ToString::to_string)
            .collect();

        if !xref_lines.is_empty() {
            candidates_with_refs.push((candidate, xref_lines));
        }
    }

    tracing::debug!(
        "verify_xor_keys: {} candidates have at least one reference",
        candidates_with_refs.len()
    );

    // If we found very few candidates with references, fall back to analyzing all candidates
    if candidates_with_refs.len() < 10 {
        tracing::debug!(
            "verify_xor_keys: too few candidates with references ({}), falling back to pattern-based analysis",
            candidates_with_refs.len()
        );

        // Fall back to analyzing all candidates by XOR loop patterns without requiring xrefs
        return analyze_candidates_by_patterns(tool, path, &candidates);
    }

    // Count XOR-function references for each candidate
    tracing::debug!("verify_xor_keys: analyzing XOR-function references...");
    let mut candidates_with_xor_refs: Vec<_> = Vec::new();

    for (idx, (candidate, xref_lines)) in candidates_with_refs.iter().enumerate() {
        if idx % 20 == 0 && idx > 0 {
            tracing::debug!(
                "  analyzed {}/{} candidates with refs...",
                idx,
                candidates_with_refs.len()
            );
        }

        let mut xor_function_refs = 0;
        let total_refs = xref_lines.len();

        // Check each referencing function for XOR instructions (limit to first 10 refs per candidate)
        for xref_line in xref_lines.iter().take(10) {
            let parts: Vec<&str> = xref_line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let func_name = parts[0];

            // Disassemble the function
            let pdf_cmd = format!("pdf @ {func_name}");
            let Some(disasm) = run_tool_command(tool, path, &pdf_cmd) else {
                continue;
            };

            // Check if function contains XOR instructions
            let has_xor = disasm.contains("eor ") || disasm.contains("xor ");
            if has_xor {
                xor_function_refs += 1;
            }
        }

        // Prioritize candidates referenced by XOR-containing functions
        if xor_function_refs > 0 {
            candidates_with_xor_refs.push((
                *candidate,
                xref_lines.clone(),
                total_refs,
                xor_function_refs,
            ));
        }
    }

    // Sort by XOR-function references (descending), then total references
    candidates_with_xor_refs.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| b.2.cmp(&a.2)));

    tracing::debug!(
        "verify_xor_keys: {} candidates referenced by XOR-containing functions",
        candidates_with_xor_refs.len()
    );

    if let Some((candidate, _, total, xor_refs)) = candidates_with_xor_refs.first() {
        tracing::debug!(
            "  top candidate: '{}' @ 0x{:x}, total_refs={}, xor_func_refs={}",
            if candidate.value.len() > 30 {
                &candidate.value[..30]
            } else {
                &candidate.value
            },
            candidate.data_offset,
            total,
            xor_refs
        );
    }

    // Analyze top candidates for XOR loop patterns
    candidates_with_xor_refs
        .iter()
        .take(20) // Only analyze top 20 candidates by XOR-function reference count
        .filter_map(
            |(candidate, xref_lines, reference_count, xor_function_refs)| {
                let mut confidence = XorConfidence::Low;

                // Check each referencing function for XOR loop patterns
                for xref_line in xref_lines.iter().take(5) {
                    let parts: Vec<&str> = xref_line.split_whitespace().collect();
                    if parts.is_empty() {
                        continue;
                    }

                    let func_name = parts[0];

                    // Disassemble the function
                    // NOTE: 'aaa' analysis already ran on line 447, so just get disassembly
                    let pdf_cmd = format!("pdf @ {func_name}");
                    let Some(disasm) = run_tool_command(tool, path, &pdf_cmd) else {
                        continue;
                    };

                    // Look for XOR loop pattern:
                    // ARM: ldrb (load byte), eor (XOR), strb (store byte)
                    // x86: movzbl/movzx (load byte), xor, mov/movb (store)
                    let has_xor = disasm.contains("eor ") || disasm.contains("xor ");
                    let has_load_byte = disasm.contains("ldrb ")
                        || disasm.contains("movzbl ")
                        || disasm.contains("movzx ");
                    let has_store_byte = disasm.contains("strb ") || disasm.contains("movb ");

                    if has_xor && has_load_byte && has_store_byte {
                        confidence = XorConfidence::High;
                        break;
                    }

                    // Medium confidence: referenced in function with XOR
                    if has_xor && confidence == XorConfidence::Low {
                        confidence = XorConfidence::Medium;
                    }
                }

                // Return result if confidence is high/medium OR if multiple XOR-function references
                if confidence != XorConfidence::Low || *xor_function_refs >= 2 {
                    // Upgrade to medium confidence if multiple XOR-function refs
                    if *xor_function_refs >= 2 && confidence == XorConfidence::Low {
                        confidence = XorConfidence::Medium;
                    }

                    Some(XorKeyInfo {
                        key: candidate.value.clone(),
                        confidence,
                        reference_count: *reference_count,
                        offset: candidate.data_offset,
                    })
                } else {
                    None
                }
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available() {
        // Just test that the function doesn't panic
        let _ = is_available();
    }

    #[test]
    fn test_classify_r2_symbol() {
        assert_eq!(classify_r2_symbol("FUNC", "GLOBAL"), StringKind::FuncName);
        assert_eq!(classify_r2_symbol("FILE", "LOCAL"), StringKind::FilePath);
        assert_eq!(classify_r2_symbol("OBJECT", "GLOBAL"), StringKind::Ident);
    }

    #[test]
    fn test_classify_r2_symbol_meth() {
        assert_eq!(classify_r2_symbol("METH", "GLOBAL"), StringKind::FuncName);
        assert_eq!(classify_r2_symbol("METH", "LOCAL"), StringKind::FuncName);
    }

    #[test]
    fn test_classify_r2_symbol_unknown_type() {
        assert_eq!(classify_r2_symbol("UNKNOWN", "GLOBAL"), StringKind::Ident);
        assert_eq!(classify_r2_symbol("", ""), StringKind::Ident);
        assert_eq!(classify_r2_symbol("NOTYPE", "LOCAL"), StringKind::Ident);
    }

    #[test]
    fn test_classify_r2_symbol_object_local() {
        // OBJECT with LOCAL binding should not be Ident
        assert_eq!(classify_r2_symbol("OBJECT", "LOCAL"), StringKind::Ident);
    }

    #[test]
    fn test_extract_strings_nonexistent_file() {
        let result = extract_strings("/nonexistent/file/path", 4, false);
        // Should return None for non-existent files
        assert!(result.is_none());
    }

    #[test]
    fn test_run_tool_command_nonexistent() {
        if let Some(tool) = get_tool() {
            let result = run_tool_command(tool, "/nonexistent/file", "iz");
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_r2_string_deserialize() {
        let json = r#"{"paddr": 4096, "string": "hello", "section": ".rodata"}"#;
        let r2_str: R2String = serde_json::from_str(json).unwrap();
        assert_eq!(r2_str.paddr, 4096);
        assert_eq!(r2_str.string, "hello");
        assert_eq!(r2_str.section, ".rodata");
    }

    #[test]
    fn test_r2_symbol_deserialize() {
        let json = r#"{"paddr": 4096, "name": "_main", "section": ".text", "type": "FUNC", "bind": "GLOBAL"}"#;
        let r2_sym: R2Symbol = serde_json::from_str(json).unwrap();
        assert_eq!(r2_sym.paddr, 4096);
        assert_eq!(r2_sym.name, "_main");
        assert_eq!(r2_sym.section, Some(".text".to_string()));
        assert_eq!(r2_sym.r#type, "FUNC");
        assert_eq!(r2_sym.bind, "GLOBAL");
    }

    #[test]
    fn test_r2_symbol_deserialize_defaults() {
        // Missing optional fields should use defaults
        let json = r#"{"paddr": 4096, "name": "_main"}"#;
        let r2_sym: R2Symbol = serde_json::from_str(json).unwrap();
        assert_eq!(r2_sym.paddr, 4096);
        assert_eq!(r2_sym.name, "_main");
        assert!(r2_sym.section.is_none());
        assert_eq!(r2_sym.r#type, "");
        assert_eq!(r2_sym.bind, "");
    }

    #[test]
    fn test_extract_strings_returns_file_offsets() {
        if !is_available() {
            return;
        }
        // Use /bin/ls which exists on all Unix systems
        let result = extract_strings("/bin/ls", 4, false);
        if let Some(strings) = result {
            // /bin/ls is typically < 200KB, virtual addresses would be > 0x100000000
            let max_reasonable_offset = 0x100000; // 1MB - generous upper bound
            for s in &strings {
                assert!(
                    s.data_offset < max_reasonable_offset,
                    "Offset 0x{:x} for '{}' looks like a virtual address, not a file offset",
                    s.data_offset,
                    s.value
                );
            }
        }
    }

    #[test]
    fn test_paddr_present_in_tool_output() {
        // Verify both rizin and r2 provide paddr field
        let tool = match get_tool() {
            Some(t) => t,
            None => return,
        };

        // Check symbols JSON has paddr
        if let Some(output) = run_tool_command(tool, "/bin/ls", "isj") {
            let json: serde_json::Value = serde_json::from_str(&output).unwrap();
            if let Some(arr) = json.as_array() {
                if let Some(first) = arr.first() {
                    assert!(
                        first.get("paddr").is_some(),
                        "{} isj output missing paddr field",
                        tool
                    );
                }
            }
        }

        // Check strings JSON has paddr
        if let Some(output) = run_tool_command(tool, "/bin/ls", "izj") {
            let json: serde_json::Value = serde_json::from_str(&output).unwrap();
            if let Some(arr) = json.as_array() {
                if let Some(first) = arr.first() {
                    assert!(
                        first.get("paddr").is_some(),
                        "{} izj output missing paddr field",
                        tool
                    );
                }
            }
        }
    }
}

/// Extract IP addresses and ports from `connect()` syscall arguments.
///
/// Analyzes code to find `connect()` calls and extracts `sockaddr_in` structures
/// built in-line (common in embedded malware). Returns IP:port strings.
///
/// For large files (>10MB), skips R2 analysis (very slow) and only scans binary directly.
pub fn extract_connect_addrs(path: &str, data: &[u8]) -> Vec<ExtractedString> {
    let Some(tool) = get_tool() else {
        return Vec::new();
    };

    // Check file size - skip R2 analysis for large files (aaa is very slow)
    if data.len() > 10 * 1024 * 1024 {
        tracing::debug!(
            "extract_connect_addrs: large file, skipping R2 analysis, using binary scan only"
        );
        // Scan binary directly without R2 analysis
        return scan_binary_for_connect_addrs(data);
    }

    tracing::debug!("extract_connect_addrs: analyzing with {}", tool);

    // Analyze binary and disassemble entire .text section
    let cmd = "aaa; e scr.color=0; s entry0; pdf";
    let Some(output) = run_tool_command(tool, path, cmd) else {
        return Vec::new();
    };

    let mut results = Vec::new();
    let mut seen = HashSet::new();

    // Look for connect syscalls (283 on ARM32, 42 on x86, etc.)
    // Also look for imports of "connect" function
    let has_connect = output.contains("283")             // ARM32 connect syscall number
        || output.contains("syscall.connect")  // Named syscall
        || output.contains("sym.imp.connect"); // Imported connect

    if !has_connect {
        tracing::debug!("extract_connect_addrs: no connect syscalls found");
        return Vec::new();
    }

    tracing::debug!("extract_connect_addrs: found potential connect syscall");

    // First try parsing from disassembly
    if let Some(sockaddr) = parse_sockaddr_from_disasm(&output, data) {
        let ip_str = format!(
            "{}.{}.{}.{}",
            sockaddr.ip[0], sockaddr.ip[1], sockaddr.ip[2], sockaddr.ip[3]
        );

        let value = if sockaddr.port > 0 {
            format!("{}:{}", ip_str, sockaddr.port)
        } else {
            ip_str
        };

        if seen.insert(value.clone()) {
            results.push(ExtractedString {
                value,
                data_offset: sockaddr.offset,
                section: Some(".text".to_string()),
                method: StringMethod::InstructionPattern,
                kind: if sockaddr.port > 0 {
                    StringKind::IPPort
                } else {
                    StringKind::IP
                },
                library: Some("connect()".to_string()),
                fragments: None,
                ..Default::default()
            });
        }
    } else {
        // Fallback: scan for IP patterns directly in instruction bytes
        tracing::debug!("extract_connect_addrs: disasm parsing failed, scanning binary");
        for sockaddr in find_sockaddr_in_binary(data) {
            let ip_str = format!(
                "{}.{}.{}.{}",
                sockaddr.ip[0], sockaddr.ip[1], sockaddr.ip[2], sockaddr.ip[3]
            );

            let value = if sockaddr.port > 0 {
                format!("{}:{}", ip_str, sockaddr.port)
            } else {
                ip_str
            };

            if seen.insert(value.clone()) {
                results.push(ExtractedString {
                    value,
                    data_offset: sockaddr.offset,
                    section: Some(".text".to_string()),
                    method: StringMethod::InstructionPattern,
                    kind: if sockaddr.port > 0 {
                        StringKind::IPPort
                    } else {
                        StringKind::IP
                    },
                    library: Some("connect()".to_string()),
                    fragments: None,
                    ..Default::default()
                });
            }
        }
    }

    tracing::debug!(
        "extract_connect_addrs: found {} unique addresses",
        results.len()
    );
    results
}

/// Fast version that scans binary directly without R2 analysis (for large files).
fn scan_binary_for_connect_addrs(data: &[u8]) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    for sockaddr in find_sockaddr_in_binary(data) {
        let ip_str = format!(
            "{}.{}.{}.{}",
            sockaddr.ip[0], sockaddr.ip[1], sockaddr.ip[2], sockaddr.ip[3]
        );

        let value = if sockaddr.port > 0 {
            format!("{}:{}", ip_str, sockaddr.port)
        } else {
            ip_str
        };

        if seen.insert(value.clone()) {
            results.push(ExtractedString {
                value,
                data_offset: sockaddr.offset,
                section: Some(".text".to_string()),
                method: StringMethod::InstructionPattern,
                kind: if sockaddr.port > 0 {
                    StringKind::IPPort
                } else {
                    StringKind::IP
                },
                library: Some("connect()".to_string()),
                fragments: None,
                ..Default::default()
            });
        }
    }

    tracing::debug!(
        "scan_binary_for_connect_addrs: found {} unique addresses",
        results.len()
    );
    results
}

#[derive(Debug)]
struct SockaddrIn {
    ip: [u8; 4],
    port: u16,
    offset: u64,
}

/// Parse `sockaddr_in` structure from disassembly output.
///
/// Looks for patterns where IP bytes are loaded into registers/stack.
/// Common patterns:
/// - ARM32: mov r0, #byte; strb r0, [sp, #offset]
/// - ARM64: mov w0, #byte; strb w0, [sp, #offset]
/// - x86: movb $byte, offset(%rsp)
fn parse_sockaddr_from_disasm(disasm: &str, _data: &[u8]) -> Option<SockaddrIn> {
    let mut ip_bytes = [0u8; 4];
    let mut port: u16 = 0;
    let mut offset = 0u64;
    let mut found_count = 0;

    // ARM32 pattern: mov r0, #0x2d; strb r0, [sp, #4]
    // Look for consecutive byte stores to stack offsets 4-7 (sockaddr_in.sin_addr)
    let mut pending_byte: Option<u8> = None;

    for line in disasm.lines() {
        // Extract offset from line start (address)
        if let Some(addr_str) = line.split_whitespace().next() {
            if let Ok(addr) = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16) {
                if offset == 0 {
                    offset = addr;
                }
            }
        }

        // ARM32: mov r*, #imm (captures the immediate value)
        if line.contains(" mov ") && line.contains(", #") || line.contains(", 0x") {
            if let Some(imm_pos) = line.rfind(", ") {
                if let Some(val_str) = line[imm_pos + 2..].split_whitespace().next() {
                    if let Ok(byte_val) = parse_immediate(val_str) {
                        pending_byte = Some(byte_val);
                        continue;
                    }
                }
            }
        }

        // ARM32: strb r*, [stack_offset] (stores the byte)
        if (line.contains("strb") || line.contains("str ")) && pending_byte.is_some() {
            if let Some(sp_offset) = extract_stack_offset(line) {
                let byte_val = pending_byte.expect("checked above");
                tracing::debug!(
                    "parse_sockaddr: found byte 0x{:02x} at sp+{} from line: {}",
                    byte_val,
                    sp_offset,
                    line.trim()
                );

                // sockaddr_in: sin_family (2 bytes), sin_port (2 bytes), sin_addr (4 bytes)
                // sin_addr starts at offset 4
                // ONLY accept offsets 4, 5, 6, 7 (exact IP bytes)
                if sp_offset == 4 {
                    ip_bytes[0] = byte_val;
                    found_count += 1;
                } else if sp_offset == 5 {
                    ip_bytes[1] = byte_val;
                    found_count += 1;
                } else if sp_offset == 6 {
                    ip_bytes[2] = byte_val;
                    found_count += 1;
                } else if sp_offset == 7 {
                    ip_bytes[3] = byte_val;
                    found_count += 1;
                }
                // Extract port (offsets 2-3)
                else if (2..4).contains(&sp_offset) {
                    if sp_offset == 2 {
                        port = u16::from(byte_val) << 8;
                    } else {
                        port |= u16::from(byte_val);
                    }
                }
                pending_byte = None;
            }
        }
    }

    if found_count == 4 && !is_zero_or_invalid(&ip_bytes) {
        Some(SockaddrIn {
            ip: ip_bytes,
            port,
            offset,
        })
    } else {
        None
    }
}

fn parse_immediate(s: &str) -> Result<u8, std::num::ParseIntError> {
    let cleaned = s
        .trim_start_matches("0x")
        .trim_end_matches(|c: char| !c.is_ascii_hexdigit());
    if s.starts_with("0x") {
        u8::from_str_radix(cleaned, 16)
    } else {
        cleaned.parse::<u8>()
    }
}

fn extract_stack_offset(line: &str) -> Option<u8> {
    // Extract the raw instruction bytes (first 8 hex chars after address)
    // strb r0, [sp, #4] encodes as 0400cde5 (little-endian ARM)
    // The offset is in the first 2 hex digits
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        let hex_str = parts[1];
        // Parse instruction bytes for ARM strb: offset in first 2 chars
        if hex_str.len() >= 8 {
            // First 2 hex digits (offset in little-endian)
            if let Ok(offset) = u8::from_str_radix(&hex_str[0..2], 16) {
                return Some(offset);
            }
        }
    }

    // Fallback: Look for [sp, #offset] or [sp, offset] format
    if let Some(sp_pos) = line.find("sp,") {
        let after_sp = &line[sp_pos + 3..];
        if let Some(num_str) = after_sp
            .trim_start_matches(|c: char| c.is_whitespace() || c == '#')
            .split(&[']', ','][..])
            .next()
        {
            return parse_immediate(num_str).ok();
        }
    }
    None
}

fn is_zero_or_invalid(ip: &[u8; 4]) -> bool {
    ip.iter().all(|&b| b == 0) || ip[0] == 0 || ip[0] >= 224
}

/// Scan binary data for `sockaddr_in` patterns by looking for mov+strb instruction sequences.
/// ARM32: mov r0, #byte; strb r0, [sp, #offset]
fn find_sockaddr_in_binary(data: &[u8]) -> Vec<SockaddrIn> {
    let mut results = Vec::new();

    // Scan for ARM32 pattern: E3 A0 00 XX (mov r0, #immediate) followed by E5 CD 00 YY (strb r0, [sp, #offset])
    let mut i = 0;
    while i + 32 <= data.len() {
        // Look for sequences of 4 mov+strb pairs with offsets 4, 5, 6, 7
        let mut ip_bytes = [0u8; 4];
        let mut found = 0;

        for j in 0..32 {
            if i + j + 8 > data.len() {
                break;
            }

            // Check for mov r0, #imm: XX 00 A0 E3
            if data[i + j + 2] == 0xA0 && data[i + j + 3] == 0xE3 {
                let byte_val = data[i + j];

                // Check for strb r0, [sp, #offset]: YY 00 CD E5
                if i + j + 7 < data.len() && data[i + j + 6] == 0xCD && data[i + j + 7] == 0xE5 {
                    let offset = data[i + j + 4];

                    // Collect IP bytes at offsets 4-7
                    if offset == 4 {
                        ip_bytes[0] = byte_val;
                        found |= 1;
                    } else if offset == 5 {
                        ip_bytes[1] = byte_val;
                        found |= 2;
                    } else if offset == 6 {
                        ip_bytes[2] = byte_val;
                        found |= 4;
                    } else if offset == 7 {
                        ip_bytes[3] = byte_val;
                        found |= 8;
                    }
                }
            }
        }

        // Check if we found all 4 bytes
        if found == 15 && !is_zero_or_invalid(&ip_bytes) {
            tracing::debug!(
                "find_sockaddr_in_binary: found IP {}.{}.{}.{} at offset 0x{:x}",
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
                i
            );
            results.push(SockaddrIn {
                ip: ip_bytes,
                port: 0,
                offset: i as u64,
            });
            i += 32; // Skip past this pattern
        } else {
            i += 4;
        }
    }

    results
}
