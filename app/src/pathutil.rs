//! Path normalization for distinct-file / distinct-directory counting.
//! Limitation: symlinks/hardlinks/8.3 aliases are NOT resolved, so aliases may
//! over-count distinct files.

pub fn normalize_path(p: &str) -> String {
    let s: String = p.chars().map(|c| if c == '/' { '\\' } else { c.to_ascii_lowercase() }).collect();
    s.trim_end_matches('\\').to_string()
}

/// Parent of an already-normalized path ("" when there is none).
pub fn parent_dir(norm: &str) -> &str {
    norm.rfind('\\').map_or("", |i| &norm[..i])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalizes() {
        assert_eq!(normalize_path("C:/Users/T\\Doc.DOCX\\"), "c:\\users\\t\\doc.docx");
        assert_eq!(parent_dir("c:\\a\\b.txt"), "c:\\a");
        assert_eq!(parent_dir("b.txt"), "");
    }
}
