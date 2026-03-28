//! Automated memory secret extraction.
//!
//! Scans process memory for secrets that are only visible at runtime
//! (decrypted strings, crypto keys, API tokens, etc.). Uses three
//! complementary detection strategies:
//!
//! 1. **Differential string scanning** — tracks printable strings across
//!    snapshots and reports newly appeared ones.
//! 2. **Entropy-based detection** — identifies high-entropy regions that
//!    may contain crypto keys or encrypted data, and detects decryption
//!    (entropy decrease).
//! 3. **Known pattern matching** — regex-like patterns for API keys,
//!    tokens, URLs, PEM headers, and other structured secrets.
//!
//! Scanning can be triggered on specific syscalls, breakpoints, or
//! periodically during execution.

use std::collections::{HashMap, HashSet};

use crate::entropy;
use crate::event_log::{EventKind, EventLog, SecretCategory};
use crate::types::VirtAddr;

/// A secret found in process memory.
#[derive(Debug, Clone)]
pub struct SecretFinding {
    /// Address where the secret was found.
    pub addr: VirtAddr,
    /// Classification of the secret.
    pub category: SecretCategory,
    /// Human-readable preview (truncated for display).
    pub preview: String,
    /// Size in bytes.
    pub size: usize,
    /// Confidence score (0.0 – 1.0).
    pub confidence: f64,
    /// Which pattern matched (for KnownPattern category).
    pub pattern_name: Option<String>,
}

/// A known pattern to match in memory.
#[derive(Debug, Clone)]
pub struct SecretPattern {
    /// Name of the pattern.
    pub name: &'static str,
    /// Prefix bytes to search for.
    pub prefix: &'static [u8],
    /// Minimum total length of the secret.
    pub min_length: usize,
    /// Maximum total length of the secret.
    pub max_length: usize,
    /// Character set validator: returns true if byte is valid in this secret.
    pub valid_byte: fn(u8) -> bool,
}

/// Built-in secret patterns.
pub static KNOWN_PATTERNS: &[SecretPattern] = &[
    // AWS Access Key ID
    SecretPattern {
        name: "AWS Access Key",
        prefix: b"AKIA",
        min_length: 20,
        max_length: 20,
        valid_byte: is_base64_char,
    },
    // AWS Secret Key (often starts with alphanumeric after AKIA key)
    SecretPattern {
        name: "AWS Secret Key",
        prefix: b"aws_secret_access_key",
        min_length: 40,
        max_length: 80,
        valid_byte: |b| is_printable_nonspace(b),
    },
    // PEM private key header
    SecretPattern {
        name: "PEM Private Key",
        prefix: b"-----BEGIN ",
        min_length: 50,
        max_length: 8192,
        valid_byte: |b| is_printable(b) || b == b'\n' || b == b'\r',
    },
    // Bearer token
    SecretPattern {
        name: "Bearer Token",
        prefix: b"Bearer ",
        min_length: 20,
        max_length: 2048,
        valid_byte: |b| is_printable_nonspace(b),
    },
    // GitHub personal access token
    SecretPattern {
        name: "GitHub Token",
        prefix: b"ghp_",
        min_length: 40,
        max_length: 40,
        valid_byte: is_alnum,
    },
    // GitHub fine-grained token
    SecretPattern {
        name: "GitHub Fine-Grained Token",
        prefix: b"github_pat_",
        min_length: 50,
        max_length: 120,
        valid_byte: |b| is_alnum(b) || b == b'_',
    },
    // Generic API key pattern (common header)
    SecretPattern {
        name: "API Key Header",
        prefix: b"api_key",
        min_length: 10,
        max_length: 128,
        valid_byte: |b| is_printable_nonspace(b),
    },
    // JWT token (starts with eyJ which is base64 of {"  )
    SecretPattern {
        name: "JWT Token",
        prefix: b"eyJ",
        min_length: 30,
        max_length: 4096,
        valid_byte: |b| is_base64_char(b) || b == b'.',
    },
    // Base64-encoded data (long runs)
    SecretPattern {
        name: "Base64 Blob",
        prefix: b"",
        min_length: 44, // 32 bytes encoded = 44 chars
        max_length: 0,  // Special: detected by entropy, not prefix
        valid_byte: is_base64_char,
    },
    // Hex-encoded key (32+ hex chars = 16+ bytes)
    SecretPattern {
        name: "Hex Key",
        prefix: b"",
        min_length: 32,
        max_length: 0,
        valid_byte: is_hex_char,
    },
];

fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

fn is_printable_nonspace(b: u8) -> bool {
    (0x21..=0x7e).contains(&b)
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

fn is_hex_char(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Configuration for the secret scanner.
#[derive(Debug, Clone)]
pub struct SecretScanConfig {
    /// Minimum string length for differential scanning.
    pub min_string_length: usize,
    /// Entropy threshold for "high entropy" classification (0.0–8.0).
    pub high_entropy_threshold: f64,
    /// Minimum entropy drop to classify as "decrypted" (delta).
    pub decryption_entropy_delta: f64,
    /// Block size for entropy analysis (bytes).
    pub entropy_block_size: usize,
    /// Enable differential string scanning.
    pub scan_new_strings: bool,
    /// Enable entropy-based scanning.
    pub scan_entropy: bool,
    /// Enable known pattern scanning.
    pub scan_patterns: bool,
    /// Maximum region size to scan (skip very large mappings).
    pub max_region_size: usize,
    /// Syscall numbers that trigger a scan (e.g., write=1, sendto=44).
    pub trigger_syscalls: HashSet<u64>,
}

impl Default for SecretScanConfig {
    fn default() -> Self {
        Self {
            min_string_length: 8,
            high_entropy_threshold: 6.5,
            decryption_entropy_delta: 2.0,
            entropy_block_size: 256,
            scan_new_strings: true,
            scan_entropy: true,
            scan_patterns: true,
            max_region_size: 16 * 1024 * 1024, // 16 MB
            trigger_syscalls: [1, 44, 46].into_iter().collect(), // write, sendto, sendmsg
        }
    }
}

/// Snapshot of strings found in a memory region.
#[derive(Debug, Clone)]
struct RegionSnapshot {
    strings: HashSet<String>,
    block_entropies: Vec<(u64, f64)>, // (addr, entropy)
}

/// The secret scanner, maintaining state across scans.
#[derive(Debug)]
pub struct SecretScanner {
    config: SecretScanConfig,
    /// Previous scan snapshots keyed by (region_start, region_end).
    previous_snapshots: HashMap<(u64, u64), RegionSnapshot>,
    /// All secrets found so far (deduplicated by address).
    found_secrets: HashMap<u64, SecretFinding>,
}

impl SecretScanner {
    /// Create a new scanner with the given configuration.
    pub fn new(config: SecretScanConfig) -> Self {
        Self {
            config,
            previous_snapshots: HashMap::new(),
            found_secrets: HashMap::new(),
        }
    }

    /// Create a scanner with default configuration.
    pub fn default_config() -> Self {
        Self::new(SecretScanConfig::default())
    }

    /// Get the configuration (mutable).
    pub fn config_mut(&mut self) -> &mut SecretScanConfig {
        &mut self.config
    }

    /// Check if a syscall number should trigger a scan.
    pub fn should_trigger_on_syscall(&self, number: u64) -> bool {
        self.config.trigger_syscalls.contains(&number)
    }

    /// Get all unique secrets found so far.
    pub fn findings(&self) -> Vec<&SecretFinding> {
        self.found_secrets.values().collect()
    }

    /// Clear previous snapshots (e.g., after process restart).
    pub fn reset(&mut self) {
        self.previous_snapshots.clear();
        self.found_secrets.clear();
    }

    /// Scan a memory region and return new findings.
    ///
    /// `data` is the contents of the region at `[base_addr, base_addr + data.len())`.
    /// Compares against the previous snapshot for differential detection.
    pub fn scan_region(
        &mut self,
        base_addr: u64,
        data: &[u8],
        event_log: &mut EventLog,
    ) -> Vec<SecretFinding> {
        if data.len() > self.config.max_region_size {
            return Vec::new();
        }

        let region_key = (base_addr, base_addr + data.len() as u64);
        let mut findings = Vec::new();

        // 1. Differential string scanning
        if self.config.scan_new_strings {
            let current_strings = extract_printable_strings(data, self.config.min_string_length);
            let current_set: HashSet<String> =
                current_strings.iter().map(|(_, s)| s.clone()).collect();

            if let Some(prev) = self.previous_snapshots.get(&region_key) {
                for (offset, s) in &current_strings {
                    if !prev.strings.contains(s) && looks_like_secret(s) {
                        let addr = base_addr + *offset as u64;
                        let finding = SecretFinding {
                            addr: VirtAddr(addr),
                            category: SecretCategory::NewString,
                            preview: truncate_preview(s, 60),
                            size: s.len(),
                            confidence: score_string_secret(s),
                            pattern_name: None,
                        };
                        findings.push(finding);
                    }
                }
            }

            // Update snapshot with current strings
            let snapshot = self
                .previous_snapshots
                .entry(region_key)
                .or_insert_with(|| RegionSnapshot {
                    strings: HashSet::new(),
                    block_entropies: Vec::new(),
                });
            snapshot.strings = current_set;
        }

        // 2. Entropy-based detection
        if self.config.scan_entropy && data.len() >= self.config.entropy_block_size {
            let blocks =
                entropy::block_entropy(data, base_addr, self.config.entropy_block_size);
            let current_entropies: Vec<(u64, f64)> =
                blocks.iter().map(|b| (b.addr, b.entropy)).collect();

            if let Some(prev) = self.previous_snapshots.get(&region_key) {
                // Detect entropy decrease (potential decryption)
                for (addr, new_ent) in &current_entropies {
                    if let Some((_, old_ent)) = prev
                        .block_entropies
                        .iter()
                        .find(|(a, _)| a == addr)
                    {
                        let delta = old_ent - new_ent;
                        if delta >= self.config.decryption_entropy_delta
                            && *old_ent >= self.config.high_entropy_threshold
                            && *new_ent < self.config.high_entropy_threshold
                        {
                            let offset = (addr - base_addr) as usize;
                            let block_end =
                                (offset + self.config.entropy_block_size).min(data.len());
                            let block_data = &data[offset..block_end];
                            let preview = format_hex_preview(block_data, 32);
                            let finding = SecretFinding {
                                addr: VirtAddr(*addr),
                                category: SecretCategory::Decrypted,
                                preview,
                                size: block_end - offset,
                                confidence: (delta / 4.0).min(1.0),
                                pattern_name: None,
                            };
                            findings.push(finding);
                        }
                    }
                }

                // Detect new high-entropy regions
                for (addr, ent) in &current_entropies {
                    if *ent >= self.config.high_entropy_threshold {
                        let was_high = prev
                            .block_entropies
                            .iter()
                            .any(|(a, e)| a == addr && *e >= self.config.high_entropy_threshold);
                        if !was_high {
                            let finding = SecretFinding {
                                addr: VirtAddr(*addr),
                                category: SecretCategory::HighEntropy,
                                preview: format!("entropy={:.2}", ent),
                                size: self.config.entropy_block_size,
                                confidence: (*ent - self.config.high_entropy_threshold) / 1.5,
                                pattern_name: None,
                            };
                            findings.push(finding);
                        }
                    }
                }
            }

            // Update entropy snapshot
            let snapshot = self
                .previous_snapshots
                .entry(region_key)
                .or_insert_with(|| RegionSnapshot {
                    strings: HashSet::new(),
                    block_entropies: Vec::new(),
                });
            snapshot.block_entropies = current_entropies;
        }

        // 3. Known pattern scanning
        if self.config.scan_patterns {
            for finding in scan_known_patterns(data, base_addr) {
                if !self.found_secrets.contains_key(&finding.addr.addr()) {
                    findings.push(finding);
                }
            }
        }

        // Record findings in event log and dedup store
        for finding in &findings {
            if !self.found_secrets.contains_key(&finding.addr.addr()) {
                event_log.record(EventKind::SecretFound {
                    addr: finding.addr,
                    category: finding.category,
                    preview: finding.preview.clone(),
                    size: finding.size,
                });
                self.found_secrets
                    .insert(finding.addr.addr(), finding.clone());
            }
        }

        findings
    }

    /// Scan multiple memory regions.
    ///
    /// `read_mem` reads `len` bytes from `addr` in the tracee.
    pub fn scan_regions<F>(
        &mut self,
        regions: &[(u64, u64, bool)], // (start, end, is_writable)
        read_mem: &F,
        event_log: &mut EventLog,
    ) -> Vec<SecretFinding>
    where
        F: Fn(u64, usize) -> Option<Vec<u8>>,
    {
        let mut all_findings = Vec::new();

        for &(start, end, is_writable) in regions {
            // Focus on writable regions (stack, heap, data) where secrets live
            if !is_writable {
                continue;
            }
            let size = (end - start) as usize;
            if size > self.config.max_region_size {
                continue;
            }
            if let Some(data) = read_mem(start, size) {
                let findings = self.scan_region(start, &data, event_log);
                all_findings.extend(findings);
            }
        }

        all_findings
    }
}

/// Extract printable ASCII strings from a byte buffer.
fn extract_printable_strings(data: &[u8], min_length: usize) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    let mut start = None;

    for (i, &b) in data.iter().enumerate() {
        if is_printable(b) || b == b'\t' {
            if start.is_none() {
                start = Some(i);
            }
        } else {
            if let Some(s) = start.take() {
                let len = i - s;
                if len >= min_length {
                    let text = String::from_utf8_lossy(&data[s..i]).into_owned();
                    results.push((s, text));
                }
            }
        }
    }
    // Handle string at end of buffer
    if let Some(s) = start {
        let len = data.len() - s;
        if len >= min_length {
            let text = String::from_utf8_lossy(&data[s..]).into_owned();
            results.push((s, text));
        }
    }

    results
}

/// Heuristic check: does this string look like it could be a secret?
fn looks_like_secret(s: &str) -> bool {
    // Skip common non-secret strings
    if s.len() < 8 {
        return false;
    }
    // Strings that are all the same char are not secrets
    let first = s.as_bytes()[0];
    if s.bytes().all(|b| b == first) {
        return false;
    }
    // Very low entropy strings are not secrets (repeated patterns)
    let ent = entropy::shannon_entropy(s.as_bytes());
    if ent < 2.5 {
        return false;
    }
    // Strings with mixed case and/or digits are more likely secrets
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_special = s.bytes().any(|b| !b.is_ascii_alphanumeric() && b != b' ');

    // At least 2 of 4 character classes
    let classes = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    classes >= 2
}

/// Score how likely a string is to be a secret (0.0 – 1.0).
fn score_string_secret(s: &str) -> f64 {
    let mut score = 0.0;
    let ent = entropy::shannon_entropy(s.as_bytes());

    // High entropy = more likely secret
    if ent > 4.0 {
        score += 0.3_f64;
    }
    if ent > 5.0 {
        score += 0.2_f64;
    }

    // Length in the sweet spot for keys/tokens
    if (16..=128).contains(&s.len()) {
        score += 0.2_f64;
    }

    // Contains equals sign (Base64 padding, key=value)
    if s.contains('=') {
        score += 0.1_f64;
    }

    // Starts with a known prefix
    for pat in KNOWN_PATTERNS {
        if !pat.prefix.is_empty() && s.as_bytes().starts_with(pat.prefix) {
            score += 0.3_f64;
            break;
        }
    }

    score.min(1.0_f64)
}

/// Scan data for known secret patterns.
fn scan_known_patterns(data: &[u8], base_addr: u64) -> Vec<SecretFinding> {
    let mut findings = Vec::new();

    for pattern in KNOWN_PATTERNS {
        if pattern.prefix.is_empty() {
            continue; // Skip patterns without a prefix (entropy-based only)
        }

        let prefix = pattern.prefix;
        if prefix.len() > data.len() {
            continue;
        }

        for i in 0..data.len().saturating_sub(prefix.len()) {
            if &data[i..i + prefix.len()] != prefix {
                continue;
            }

            // Found prefix, now validate the full match
            let mut end = i + prefix.len();
            while end < data.len()
                && end - i < pattern.max_length
                && (pattern.valid_byte)(data[end])
            {
                end += 1;
            }

            let match_len = end - i;
            if match_len >= pattern.min_length {
                let preview = truncate_preview(
                    &String::from_utf8_lossy(&data[i..end]),
                    60,
                );
                findings.push(SecretFinding {
                    addr: VirtAddr(base_addr + i as u64),
                    category: SecretCategory::KnownPattern,
                    preview,
                    size: match_len,
                    confidence: 0.8,
                    pattern_name: Some(pattern.name.to_string()),
                });
            }
        }
    }

    findings
}

/// Truncate a string for preview display.
fn truncate_preview(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Format bytes as a hex preview string.
fn format_hex_preview(data: &[u8], max_bytes: usize) -> String {
    let display = &data[..data.len().min(max_bytes)];
    let hex: Vec<String> = display.iter().map(|b| format!("{:02x}", b)).collect();
    let mut result = hex.join(" ");
    if data.len() > max_bytes {
        result.push_str("...");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_printable_strings_basic() {
        let data = b"\x00\x00hello world\x00\x01\x02short\x00this is a longer string\x00";
        let strings = extract_printable_strings(data, 8);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].1, "hello world");
        assert_eq!(strings[1].1, "this is a longer string");
    }

    #[test]
    fn extract_strings_min_length() {
        let data = b"hi\x00hello world\x00";
        let strings = extract_printable_strings(data, 5);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].1, "hello world");
    }

    #[test]
    fn looks_like_secret_basic() {
        assert!(looks_like_secret("AKIAxyz123ABCdef4567")); // AWS-like key
        assert!(looks_like_secret("ghp_1234567890abcdefghijklmnopqrstuvwxyz"));
        assert!(!looks_like_secret("hello")); // too short
        assert!(!looks_like_secret("aaaaaaaaaa")); // all same char
        assert!(!looks_like_secret("        ")); // spaces only
    }

    #[test]
    fn score_string_secret_ranges() {
        let high = score_string_secret("AKIA1234ABCD5678efgh");
        let low = score_string_secret("hello world foo bar");
        assert!(high > low);
        assert!(high > 0.5);
    }

    #[test]
    fn known_pattern_aws_key() {
        let data = b"config: AKIAIOSFODNN7EXAMPLE more data";
        let findings = scan_known_patterns(data, 0x1000);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_name.as_deref(), Some("AWS Access Key"));
        assert_eq!(findings[0].addr, VirtAddr(0x1008));
        assert_eq!(findings[0].size, 20);
    }

    #[test]
    fn known_pattern_github_token() {
        let mut data = Vec::new();
        data.extend_from_slice(b"token=ghp_");
        // 36 alnum chars → total "ghp_" + 36 = 40 (meets min_length)
        data.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz1234567890");
        data.push(b' ');

        let findings = scan_known_patterns(&data, 0x2000);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_name.as_deref(), Some("GitHub Token"));
    }

    #[test]
    fn known_pattern_pem_key() {
        let mut data = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        data.extend_from_slice(&[b'A'; 50]);
        let findings = scan_known_patterns(&data, 0x3000);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_name.as_deref(), Some("PEM Private Key"));
    }

    #[test]
    fn known_pattern_jwt() {
        // eyJ is base64 of '{"' — typical JWT start
        let data = b"auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0 end";
        let findings = scan_known_patterns(data, 0x4000);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_name.as_deref(), Some("JWT Token"));
    }

    #[test]
    fn differential_string_scan() {
        let mut scanner = SecretScanner::new(SecretScanConfig {
            scan_entropy: false,
            scan_patterns: false,
            min_string_length: 8,
            ..Default::default()
        });
        let mut log = EventLog::new();

        // Both scans use the same buffer size so region keys match.
        // First scan: establish baseline with padding
        let mut data1 = vec![0u8; 64];
        data1[2..20].copy_from_slice(b"normal_string_here");

        let findings = scanner.scan_region(0x1000, &data1, &mut log);
        assert!(findings.is_empty()); // No previous snapshot, nothing is "new"

        // Second scan: same size, old string stays, new secret-like string added
        let mut data2 = vec![0u8; 64];
        data2[2..20].copy_from_slice(b"normal_string_here");
        let secret = b"SecretKey=aB3xZ9qW2";
        data2[21..21 + secret.len()].copy_from_slice(secret);

        let findings = scanner.scan_region(0x1000, &data2, &mut log);

        // The new string should be detected
        let new_strings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == SecretCategory::NewString)
            .collect();
        assert_eq!(new_strings.len(), 1);
        assert!(new_strings[0].preview.contains("SecretKey"));
    }

    #[test]
    fn truncate_preview_short() {
        assert_eq!(truncate_preview("hello", 10), "hello");
    }

    #[test]
    fn truncate_preview_long() {
        let long = "a".repeat(100);
        let preview = truncate_preview(&long, 20);
        assert_eq!(preview.len(), 23); // 20 + "..."
        assert!(preview.ends_with("..."));
    }

    #[test]
    fn format_hex_preview_basic() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(format_hex_preview(&data, 10), "de ad be ef");
    }

    #[test]
    fn format_hex_preview_truncated() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let preview = format_hex_preview(&data, 3);
        assert_eq!(preview, "01 02 03...");
    }

    #[test]
    fn trigger_syscall_check() {
        let scanner = SecretScanner::default_config();
        assert!(scanner.should_trigger_on_syscall(1)); // write
        assert!(scanner.should_trigger_on_syscall(44)); // sendto
        assert!(!scanner.should_trigger_on_syscall(0)); // read — not a trigger
    }

    #[test]
    fn findings_deduplication() {
        let mut scanner = SecretScanner::new(SecretScanConfig {
            scan_new_strings: false,
            scan_entropy: false,
            scan_patterns: true,
            ..Default::default()
        });
        let mut log = EventLog::new();

        let data = b"key=AKIAIOSFODNN7EXAMPLE end";

        // Scan twice — same findings should not be duplicated
        let f1 = scanner.scan_region(0x1000, data, &mut log);
        let f2 = scanner.scan_region(0x1000, data, &mut log);

        assert_eq!(f1.len(), 1);
        assert!(f2.is_empty()); // Deduplicated
        assert_eq!(scanner.findings().len(), 1);
    }

    #[test]
    fn reset_clears_state() {
        let mut scanner = SecretScanner::default_config();
        let mut log = EventLog::new();

        let data = b"\x00AKIAIOSFODNN7EXAMPLE\x00";
        scanner.scan_region(0x1000, data, &mut log);
        assert!(!scanner.findings().is_empty());

        scanner.reset();
        assert!(scanner.findings().is_empty());
    }

    #[test]
    fn scan_regions_filters_writable() {
        let mut scanner = SecretScanner::new(SecretScanConfig {
            scan_new_strings: false,
            scan_entropy: false,
            scan_patterns: true,
            ..Default::default()
        });
        let mut log = EventLog::new();

        let regions = vec![
            (0x1000, 0x1100, false), // read-only (code) — skipped
            (0x2000, 0x2100, true),  // writable (data) — scanned
        ];

        let data_store = b"\x00AKIAIOSFODNN7EXAMPLE\x00";
        let read_mem = |addr: u64, _len: usize| -> Option<Vec<u8>> {
            if addr == 0x2000 {
                Some(data_store.to_vec())
            } else {
                Some(vec![0u8; 256])
            }
        };

        let findings = scanner.scan_regions(&regions, &read_mem, &mut log);
        assert_eq!(findings.len(), 1);
    }
}
