//! Port of `featurize` in `ai/lotl/features.py`, which is the specification:
//! the same record must give the same tags and numbers on both sides.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use regex::Regex;

use super::model::ExtractorConfig;
use crate::core::features::chains::{log_complexity, shannon_entropy};

pub struct Featurizer {
    /// In `image_class` precedence order.
    classes: [(&'static str, HashSet<String>); 4],
    known: HashSet<String>,
    paths: Vec<(String, String)>,
    long_params: HashSet<String>,
    rules: Vec<(String, String)>,
    patterns: Vec<(String, Regex)>,
    /// Runs of digits and dots: IPv4 candidates (`_IPV4` lookarounds reject partial runs).
    digit_runs: Regex,
    ipv4: Regex,
    url: Regex,
    domain: Regex,
}

impl Featurizer {
    pub fn new(cfg: &ExtractorConfig) -> Result<Self, String> {
        let set = |v: &[String]| v.iter().cloned().collect::<HashSet<_>>();
        let classes = [
            ("CONTENT", set(&cfg.content_apps)),
            ("INTERP", set(&cfg.interpreters)),
            ("TOOL", set(&cfg.tools)),
            ("SERVER", set(&cfg.servers)),
        ];
        let mut known = set(&cfg.lotl_bins);
        for (_, members) in &classes {
            known.extend(members.iter().cloned());
        }
        let rx = |re: &str| Regex::new(re).map_err(|e| format!("pattern {re}: {e}"));
        let patterns = cfg
            .patterns
            .iter()
            .map(|(name, re)| Ok((name.clone(), rx(&format!("(?i){re}"))?)))
            .collect::<Result<_, String>>()?;
        Ok(Featurizer {
            classes,
            known,
            paths: cfg.paths.clone(),
            long_params: set(&cfg.long_params),
            rules: cfg.cmdline_rules.clone(),
            patterns,
            digit_runs: rx(r"[\d.]+")?,
            ipv4: rx(r"^\d{1,3}(?:\.\d{1,3}){3}$")?,
            url: rx(r"(?i)\b(https?|ftp|tftp|smb|ldap)://")?,
            domain: rx(r"(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|ru|cn|xyz|top|sh|me|co|onion|tk)\b")?,
        })
    }

    /// Known name, also behind a version suffix (python3.12 -> python, php8 -> php, apache2 stays).
    fn base<'a>(&self, img: &'a str) -> &'a str {
        if self.known.contains(img) {
            return img;
        }
        let b = img.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
        if b.is_empty() { img } else { b }
    }

    pub fn image_class(&self, img: &str) -> &'static str {
        let b = self.base(img);
        self.classes.iter().find(|(_, members)| members.contains(b)).map_or("OTHER", |(name, _)| name)
    }

    fn known<'a>(&self, img: &'a str) -> &'a str {
        let b = self.base(img);
        if self.known.contains(b) { b } else { "OTHER" }
    }

    /// Command-line rule labels plus `pipe_to_interpreter`; deduplicated, in rule order.
    pub fn rule_hits(&self, cmdline: &str) -> Vec<&str> {
        self.rule_hits_norm(&normalize(cmdline))
    }

    fn rule_hits_norm(&self, norm: &str) -> Vec<&str> {
        let mut hits: Vec<&str> = Vec::new();
        let mut add = |h| {
            if !hits.contains(&h) {
                hits.push(h);
            }
        };
        for (frag, label) in &self.rules {
            if contains_word(norm, frag) {
                add(label.as_str());
            }
        }
        // `... | sh`, `... | sudo python3`: whatever runs after a pipe is an interpreter.
        for seg in norm.split('|').skip(1) {
            let first = seg.split(' ').find(|w| !w.is_empty() && *w != "sudo");
            if first.is_some_and(|w| self.image_class(w.rsplit('/').next().unwrap_or(w)) == "INTERP") {
                add("pipe_to_interpreter");
            }
        }
        hits
    }

    pub fn featurize(&self, chain: &[String], cmdline: &str) -> HashMap<String, f64> {
        let mut chain: Vec<String> = chain.iter().map(|c| c.to_lowercase()).collect();
        if chain.is_empty() {
            chain.push(String::new());
        }
        let img = chain[chain.len() - 1].as_str();
        let parent = if chain.len() > 1 { chain[chain.len() - 2].as_str() } else { "" };
        let ancestors = &chain[..chain.len() - 1];
        let mut f: HashMap<String, f64> = HashMap::new();
        let mut tag = |t: String| {
            f.insert(t, 1.0);
        };

        // Chain: who spawned whom, by known name and by class.
        let ic = self.image_class(img);
        let pc = if parent.is_empty() { "NONE" } else { self.image_class(parent) };
        tag(format!("IMG_{}", self.known(img)));
        tag(format!("IMG_CLASS_{ic}"));
        tag(format!("PARENT_{}", if parent.is_empty() { "NONE" } else { self.known(parent) }));
        tag(format!("PARENT_CLASS_{pc}"));
        tag(format!("PAIR_CLASS_{pc}>{ic}"));
        if chain.len() > 2 {
            tag(format!("GPARENT_CLASS_{}", self.image_class(&chain[chain.len() - 3])));
        }
        for a in ancestors {
            let ac = self.image_class(a);
            if ac == "CONTENT" || ac == "SERVER" {
                tag(format!("ANCESTOR_{ac}"));
            }
        }
        let interp_run = chain.iter().rev().take_while(|c| self.image_class(c) == "INTERP").count();

        // Command line, paper §3.2 tag classes.
        let norm = normalize(cmdline);
        let toks = tokens(cmdline);
        for t in &toks {
            let slashed = t.replace('\\', "/");
            let name = slashed.rsplit('/').next().unwrap_or("").to_lowercase();
            let name = name.strip_suffix(".exe").unwrap_or(&name);
            let k = self.known(name);
            if k != "OTHER" {
                tag(format!("CMD_{k}"));
            }
            let tl = t.to_lowercase();
            let mut cs = t.chars();
            let short = cs.next() == Some('-') && cs.next().is_some_and(|c| c.is_ascii_alphabetic()) && cs.next().is_none();
            if short || self.long_params.contains(&tl) {
                tag(format!("PARAM_{}", if t.chars().count() == 2 { t } else { &tl }));
            }
        }
        for (frag, label) in &self.paths {
            if norm.contains(frag.as_str()) {
                tag(format!("PATH_{label}"));
            }
        }
        for m in self.digit_runs.find_iter(cmdline) {
            // Python's `ipaddress` also rejects octets above 255 and leading zeros.
            let Some(ip) = Some(m.as_str()).filter(|s| self.ipv4.is_match(s)).and_then(|s| s.parse::<Ipv4Addr>().ok())
            else {
                continue;
            };
            let [a, b, ..] = ip.octets();
            let internal = a == 10
                || (a == 172 && (16..32).contains(&b))
                || (a == 192 && b == 168)
                || (a == 169 && b == 254)
                || (a == 100 && (64..128).contains(&b));
            tag((if ip.is_loopback() { "IP_LOOPBACK" } else if internal { "IP_PRIVATE" } else { "IP_PUBLIC" }).into());
        }
        for c in self.url.captures_iter(cmdline) {
            tag(format!("URL_{}", c[1].to_uppercase()));
        }
        if self.domain.is_match(cmdline) {
            tag("DOMAIN".into());
        }
        for label in self.rule_hits_norm(&norm) {
            tag(format!("RULE_{label}"));
        }
        for (name, rx) in &self.patterns {
            if rx.is_match(cmdline) {
                tag(format!("PAT_{name}"));
            }
        }

        let n_tags = f.len() as f64;
        f.extend([
            ("num_depth", ancestors.len() as f64),
            ("num_interp_run", interp_run as f64),
            ("num_cmdline_len", cmdline.chars().count() as f64),
            ("num_cmdline_entropy", shannon_entropy(cmdline)),
            ("num_cmdline_complexity", log_complexity(cmdline)),
            ("num_image_complexity", log_complexity(img)),
            ("num_args", toks.len() as f64),
            ("num_pipes", norm.matches('|').count() as f64),
            ("num_tags", n_tags),
        ]
        .map(|(k, v)| (k.to_string(), v)));
        f
    }
}

/// Python `str.split()`: runs of whitespace, where Python also counts U+001C..U+001F.
fn py_split(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)).filter(|w| !w.is_empty())
}

/// Lowercase, single spaces, none around pipes.
fn normalize(cmdline: &str) -> String {
    py_split(&cmdline.to_lowercase()).collect::<Vec<_>>().join(" ").replace(" |", "|").replace("| ", "|")
}

/// Python `shlex.split(cmdline)`, falling back to `str.split()` on unbalanced quotes
/// or a trailing backslash, as `_tokens` does.
fn tokens(cmdline: &str) -> Vec<String> {
    shlex_split(cmdline).unwrap_or_else(|| py_split(cmdline).map(String::from).collect())
}

/// Port of CPython's posix `shlex` with `whitespace_split=True` and no comments
/// (the `shlex` crate differs: it treats `#` as a comment and unescapes `\$` in
/// double quotes).
fn shlex_split(s: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy)]
    enum St {
        Space,
        Word,
        Quote(char),
        /// After a backslash; returns to the word, or to the double quote.
        Escape(Option<char>),
    }
    let (mut out, mut tok, mut quoted, mut st) = (Vec::new(), String::new(), false, St::Space);
    let mut chars = s.chars();
    loop {
        let c = chars.next();
        st = match (st, c) {
            (St::Space, None) => break,
            (St::Space, Some(' ' | '\t' | '\r' | '\n')) => St::Space,
            (St::Space | St::Word, Some('\\')) => St::Escape(None),
            (St::Space | St::Word, Some(q @ ('\'' | '"'))) => St::Quote(q),
            (St::Space | St::Word, Some(c)) if !matches!(c, ' ' | '\t' | '\r' | '\n') => {
                tok.push(c);
                St::Word
            }
            (St::Word, _) => {
                // End of input or whitespace: emit (an empty token only if it was quoted).
                if !tok.is_empty() || quoted {
                    out.push(std::mem::take(&mut tok));
                }
                quoted = false;
                if c.is_none() {
                    break;
                }
                St::Space
            }
            (St::Quote(_), None) | (St::Escape(_), None) => return None,
            (St::Quote(q), Some(c)) => {
                quoted = true;
                match c {
                    _ if c == q => St::Word,
                    '\\' if q == '"' => St::Escape(Some(q)),
                    _ => {
                        tok.push(c);
                        St::Quote(q)
                    }
                }
            }
            (St::Escape(back), Some(c)) => {
                // Inside double quotes only `\"` and `\\` are escapes; elsewhere the backslash stays.
                if back.is_some_and(|q| c != '\\' && c != q) {
                    tok.push('\\');
                }
                tok.push(c);
                back.map_or(St::Word, St::Quote)
            }
            (St::Space, Some(_)) => unreachable!("whitespace handled above"),
        };
    }
    Some(out)
}

/// `pat` in `s` not glued to a longer word ("| sh" must not match "| sha256sum");
/// overlapping occurrences are tried, like Python's `_contains_word`.
fn contains_word(s: &str, pat: &str) -> bool {
    let (Some(first), Some(last)) = (pat.chars().next(), pat.chars().next_back()) else {
        return false;
    };
    let mut from = 0;
    while let Some(i) = s[from..].find(pat).map(|i| i + from) {
        let before = s[..i].chars().next_back();
        let after = s[i + pat.len()..].chars().next();
        let open = !first.is_alphanumeric() || !before.is_some_and(char::is_alphanumeric);
        let close = !last.is_alphanumeric() || !after.is_some_and(|c| c.is_alphabetic() || c == '_');
        if open && close {
            return true;
        }
        from = i + s[i..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::super::model::tests::fixture;
    use super::*;

    #[test]
    fn featurize_matches_python() {
        let (model, cases) = fixture();
        for c in &cases {
            let got = model.featurizer.featurize(&c.chain, &c.cmdline);
            let mut keys: Vec<_> = got.keys().collect();
            let mut want: Vec<_> = c.features.keys().collect();
            keys.sort();
            want.sort();
            assert_eq!(keys, want, "{:?} {}", c.chain, c.cmdline);
            for (k, v) in &c.features {
                assert_eq!(got[k] as f32, *v as f32, "{k} of {:?} {}", c.chain, c.cmdline);
            }
        }
    }

    #[test]
    fn shlex_matches_python() {
        // Expected values from CPython 3.14 `shlex.split`.
        let cases: [(&str, Option<&[&str]>); 7] = [
            (r#"sh -c "echo \$HOME \"x\"" a\ b"#, Some(&["sh", "-c", r#"echo \$HOME "x""#, "a b"])),
            ("echo #not-a-comment ''", Some(&["echo", "#not-a-comment", ""])),
            ("a'b'\"c\" d", Some(&["abc", "d"])),
            ("x\r\ny", Some(&["x", "y"])),
            ("echo 'open", None),
            ("trailing\\", None),
            ("", Some(&[])),
        ];
        for (input, want) in cases {
            assert_eq!(shlex_split(input).as_deref(), want.map(|w| w.iter().map(|s| s.to_string()).collect::<Vec<_>>()).as_deref(), "{input:?}");
        }
        // `ipaddress.ip_address` rejects these too.
        assert!(["01.2.3.4", "256.1.1.1"].iter().all(|s| s.parse::<Ipv4Addr>().is_err()));
    }
}
