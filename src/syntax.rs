use crate::error::{HttpCliError, Result};
use std::sync::OnceLock;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::{as_24_bit_terminal_escaped, LinesWithEndings};

static SYNTAX_SET: OnceLock<SyntaxSet> = OnceLock::new();
static THEME_SET: OnceLock<ThemeSet> = OnceLock::new();

pub struct SyntaxHighlighter {
    theme_name: String,
}

impl SyntaxHighlighter {
    pub fn new(theme_name: &str) -> Result<Self> {
        Ok(Self {
            theme_name: theme_name.to_string(),
        })
    }

    pub fn highlight(&self, text: &str, language: &str) -> Result<String> {
        // Initialize syntax set once
        let syntax_set = SYNTAX_SET.get_or_init(|| SyntaxSet::load_defaults_newlines());

        // Initialize theme set once
        let theme_set = THEME_SET.get_or_init(|| ThemeSet::load_defaults());

        // Find syntax definition
        let syntax = syntax_set
            .find_syntax_by_extension(language)
            .or_else(|| syntax_set.find_syntax_by_name(language))
            .or_else(|| syntax_set.find_syntax_by_first_line(text))
            .unwrap_or_else(|| syntax_set.find_syntax_plain_text());

        // Find theme
        let theme = theme_set.themes.get(&self.theme_name).ok_or_else(|| {
            HttpCliError::syntax_highlight(format!("Theme '{}' not found", self.theme_name))
        })?;

        // Highlight text
        let mut highlighter = HighlightLines::new(syntax, theme);
        let mut highlighted = String::new();

        for line in LinesWithEndings::from(text) {
            let ranges: Vec<(Style, &str)> =
                highlighter.highlight_line(line, syntax_set).map_err(|e| {
                    HttpCliError::syntax_highlight(format!("Highlighting error: {}", e))
                })?;

            let escaped = as_24_bit_terminal_escaped(&ranges[..], false);
            highlighted.push_str(&escaped);
        }

        Ok(highlighted)
    }

    pub fn highlight_json(&self, json_text: &str) -> Result<String> {
        // First, try to pretty-print the JSON
        let pretty_json = match serde_json::from_str::<serde_json::Value>(json_text) {
            Ok(value) => {
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| json_text.to_string())
            }
            Err(_) => json_text.to_string(),
        };

        self.highlight(&pretty_json, "json")
    }

    pub fn list_themes() -> Vec<String> {
        let theme_set = THEME_SET.get_or_init(|| ThemeSet::load_defaults());
        theme_set.themes.keys().cloned().collect()
    }

    pub fn list_languages() -> Vec<String> {
        let syntax_set = SYNTAX_SET.get_or_init(|| SyntaxSet::load_defaults_newlines());
        syntax_set
            .syntaxes()
            .iter()
            .map(|s| s.name.clone())
            .collect()
    }

    /// Detect language from file extension or content
    pub fn detect_language_from_content(content: &str, filename: Option<&str>) -> &'static str {
        if let Some(filename) = filename {
            if let Some(extension) = std::path::Path::new(filename)
                .extension()
                .and_then(|ext| ext.to_str())
            {
                return Self::map_extension_to_language(extension);
            }
        }

        // Content-based detection
        let trimmed = content.trim();

        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            // Likely JSON
            if serde_json::from_str::<serde_json::Value>(content).is_ok() {
                return "json";
            }
        }

        if trimmed.starts_with('<') && (trimmed.ends_with('>') || trimmed.contains("</")) {
            if trimmed.contains("<!DOCTYPE html") || trimmed.contains("<html") {
                return "html";
            } else {
                return "xml";
            }
        }

        // Check for common patterns
        if content.contains("function ") || content.contains("const ") || content.contains("let ") {
            return "javascript";
        }

        if content.contains("def ") || content.contains("import ") || content.contains("class ") {
            return "python";
        }

        if content.contains("#include") || content.contains("int main(") {
            return "c";
        }

        if content.contains("fn ") || content.contains("use ") || content.contains("impl ") {
            return "rust";
        }

        "text"
    }

    fn map_extension_to_language(extension: &str) -> &'static str {
        match extension.to_lowercase().as_str() {
            "json" => "json",
            "xml" => "xml",
            "html" | "htm" => "html",
            "css" => "css",
            "js" | "mjs" => "javascript",
            "ts" => "typescript",
            "py" => "python",
            "rs" => "rust",
            "c" => "c",
            "cpp" | "cc" | "cxx" => "cpp",
            "h" | "hpp" => "c",
            "java" => "java",
            "go" => "go",
            "php" => "php",
            "rb" => "ruby",
            "sh" | "bash" => "bash",
            "yaml" | "yml" => "yaml",
            "toml" => "toml",
            "md" | "markdown" => "markdown",
            "sql" => "sql",
            "dockerfile" => "dockerfile",
            "makefile" => "makefile",
            "gitignore" => "gitignore",
            _ => "text",
        }
    }
}

/// Helper function to strip ANSI escape codes for plain text output
pub fn strip_ansi(text: &str) -> String {
    let ansi_regex = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    ansi_regex.replace_all(text, "").to_string()
}

/// Check if terminal supports colors
pub fn supports_color() -> bool {
    std::env::var("TERM")
        .map(|term| term != "dumb")
        .unwrap_or(false)
        && std::env::var("NO_COLOR").is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_detection() {
        assert_eq!(
            SyntaxHighlighter::detect_language_from_content(r#"{"key": "value"}"#, None),
            "json"
        );

        assert_eq!(
            SyntaxHighlighter::detect_language_from_content("<html><body></body></html>", None),
            "html"
        );

        assert_eq!(
            SyntaxHighlighter::detect_language_from_content("function test() {}", None),
            "javascript"
        );
    }

    #[test]
    fn test_extension_mapping() {
        assert_eq!(SyntaxHighlighter::map_extension_to_language("json"), "json");
        assert_eq!(SyntaxHighlighter::map_extension_to_language("rs"), "rust");
        assert_eq!(SyntaxHighlighter::map_extension_to_language("py"), "python");
    }

    #[test]
    fn test_basic_highlighting() {
        let highlighter = SyntaxHighlighter::new("base16-ocean.dark").unwrap();
        let result = highlighter.highlight(r#"{"test": true}"#, "json");
        assert!(result.is_ok());

        // The result should contain ANSI escape codes
        let highlighted = result.unwrap();
        assert!(highlighted.len() > r#"{"test": true}"#.len());
    }
}

