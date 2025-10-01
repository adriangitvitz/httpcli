use crate::error::{HttpCliError, Result};
use nom::{
    bytes::complete::{tag, take_until, take_while, take_while1},
    character::complete::{line_ending, multispace0, not_line_ending, space0, space1},
    combinator::opt,
    multi::{many0, many1},
    IResult,
};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct HttpFile {
    pub requests: Vec<HttpRequest>,
    pub variables: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub name: Option<String>,
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub variables: HashMap<String, String>,
    pub pre_request_script: Option<String>,
    pub tests: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub value: String,
}

pub struct HttpFileParser {
    variables: HashMap<String, String>,
}

impl HttpFileParser {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    pub fn with_variables(variables: HashMap<String, String>) -> Self {
        Self { variables }
    }

    pub async fn parse_file(&mut self, file_path: &Path) -> Result<HttpFile> {
        let content = tokio::fs::read_to_string(file_path).await?;
        self.parse_content(&content)
    }

    pub fn parse_content(&mut self, content: &str) -> Result<HttpFile> {
        self.load_environment_variables();

        match parse_http_file(content) {
            Ok((_, http_file)) => {
                let mut processed_file = http_file;

                processed_file.variables.extend(self.variables.clone());

                for request in &mut processed_file.requests {
                    self.process_request_variables(request, &processed_file.variables)?;
                }

                Ok(processed_file)
            }
            Err(e) => Err(HttpCliError::http_file_parser(format!(
                "Parse error: {}",
                e
            ))),
        }
    }

    fn load_environment_variables(&mut self) {
        for (key, value) in std::env::vars() {
            if key.starts_with("HTTP_") {
                let var_name = key.strip_prefix("HTTP_").unwrap();
                self.variables.insert(var_name.to_string(), value);
            }
        }
    }

    fn process_request_variables(
        &self,
        request: &mut HttpRequest,
        global_vars: &HashMap<String, String>,
    ) -> Result<()> {
        let mut all_vars = global_vars.clone();
        all_vars.extend(request.variables.clone());

        request.url = self.substitute_variables(&request.url, &all_vars)?;

        let mut processed_headers = HashMap::new();
        for (key, value) in &request.headers {
            let processed_key = self.substitute_variables(key, &all_vars)?;
            let processed_value = self.substitute_variables(value, &all_vars)?;
            processed_headers.insert(processed_key, processed_value);
        }
        request.headers = processed_headers;

        if let Some(ref body) = request.body {
            request.body = Some(self.substitute_variables(body, &all_vars)?);
        }

        Ok(())
    }

    fn substitute_variables(
        &self,
        text: &str,
        variables: &HashMap<String, String>,
    ) -> Result<String> {
        let var_regex = Regex::new(r"\{\{(\w+)\}\}")
            .map_err(|e| HttpCliError::http_file_parser(format!("Regex error: {}", e)))?;

        let mut result = text.to_string();

        for captures in var_regex.captures_iter(text) {
            if let Some(var_name) = captures.get(1) {
                let var_name_str = var_name.as_str();
                if let Some(var_value) = variables.get(var_name_str) {
                    let placeholder = format!("{{{{{}}}}}", var_name_str);
                    result = result.replace(&placeholder, var_value);
                } else {
                    return Err(HttpCliError::http_file_parser(format!(
                        "Undefined variable: {}",
                        var_name_str
                    )));
                }
            }
        }

        Ok(result)
    }
}

// Nom parsers
fn parse_http_file(input: &str) -> IResult<&str, HttpFile> {
    let (input, _) = multispace0(input)?;
    let (input, variables) = many0(parse_variable)(input)?;
    let (input, _) = multispace0(input)?;
    let (input, requests) = many1(parse_request)(input)?;

    let vars_map = variables.into_iter().map(|v| (v.name, v.value)).collect();

    Ok((
        input,
        HttpFile {
            requests,
            variables: vars_map,
        },
    ))
}

fn parse_variable(input: &str) -> IResult<&str, Variable> {
    let (input, _) = multispace0(input)?;
    let (input, _) = tag("@")(input)?;
    let (input, name) = take_while1(|c: char| c.is_alphanumeric() || c == '_')(input)?;
    let (input, _) = space0(input)?;
    let (input, _) = tag("=")(input)?;
    let (input, _) = space0(input)?;
    let (input, value) = not_line_ending(input)?;
    let (input, _) = line_ending(input)?;

    Ok((
        input,
        Variable {
            name: name.to_string(),
            value: value.trim().to_string(),
        },
    ))
}

fn parse_request(input: &str) -> IResult<&str, HttpRequest> {
    let (input, _) = multispace0(input)?;
    let (input, name) = opt(parse_request_name)(input)?;
    let (input, _) = multispace0(input)?;
    let (input, (method, url)) = parse_request_line(input)?;
    let (input, _) = line_ending(input)?;
    let (input, headers) = many0(parse_header)(input)?;
    let (input, _) = multispace0(input)?;
    let (input, body) = opt(parse_body)(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = opt(parse_separator)(input)?;

    Ok((
        input,
        HttpRequest {
            name,
            method: method.to_string(),
            url: url.to_string(),
            headers: headers.into_iter().collect(),
            body,
            variables: HashMap::new(),
            pre_request_script: None,
            tests: Vec::new(),
        },
    ))
}

fn parse_request_name(input: &str) -> IResult<&str, String> {
    let (input, _) = tag("# @name")(input)?;
    let (input, _) = space1(input)?;
    let (input, name) = not_line_ending(input)?;
    let (input, _) = line_ending(input)?;

    Ok((input, name.trim().to_string()))
}

fn parse_request_line(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, method) = take_while1(|c: char| c.is_ascii_uppercase())(input)?;
    let (input, _) = space1(input)?;
    let (input, url) = take_while1(|c: char| !c.is_whitespace())(input)?;
    let (input, _) = space0(input)?;

    Ok((input, (method, url)))
}

fn parse_header(input: &str) -> IResult<&str, (String, String)> {
    // Check if we're at an empty line or separator - if so, no more headers
    if input.trim_start().is_empty() || input.trim_start().starts_with("###") {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    // Get the current line
    let (rest, line) = not_line_ending(input)?;
    let (rest, _) = line_ending(rest)?;

    // Check if this line contains a colon (valid header format)
    if let Some(colon_pos) = line.find(':') {
        let name = line[..colon_pos].trim();
        let value = line[colon_pos + 1..].trim();

        // Skip empty header names
        if name.is_empty() {
            return Err(nom::Err::Error(nom::error::make_error(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }

        Ok((rest, (name.to_string(), value.to_string())))
    } else {
        // No colon found, this is not a header line
        Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::Tag,
        )))
    }
}

fn parse_body(input: &str) -> IResult<&str, String> {
    // Check if we're at the separator or end - no body
    if input.trim_start().is_empty() || input.trim_start().starts_with("###") {
        return Ok((input, String::new()));
    }

    // Look for the next separator to determine where the body ends
    if let Some(separator_pos) = input.find("\n###") {
        // Found separator on a new line - body ends there
        let body = input[..separator_pos].trim().to_string();
        let remaining = &input[separator_pos + 1..]; // Skip the newline before ###
        Ok((remaining, body))
    } else if let Some(separator_pos) = input.find("###") {
        // Found separator immediately - body ends there
        let body = input[..separator_pos].trim().to_string();
        let remaining = &input[separator_pos..];
        Ok((remaining, body))
    } else {
        // No separator found - body goes to end of input
        let body = input.trim().to_string();
        Ok(("", body))
    }
}

fn parse_separator(input: &str) -> IResult<&str, ()> {
    let (input, _) = tag("###")(input)?;
    let (input, _) = take_while(|c: char| c == '#')(input)?;
    let (input, _) = multispace0(input)?;

    Ok((input, ()))
}

impl Default for HttpFileParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_request() {
        let content = r#"
GET https://api.example.com/users
Content-Type: application/json
Authorization: Bearer token123

###
"#;

        let mut parser = HttpFileParser::new();
        let result = parser.parse_content(content).unwrap();

        assert_eq!(result.requests.len(), 1);

        let request = &result.requests[0];
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "https://api.example.com/users");
        assert_eq!(
            request.headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(
            request.headers.get("Authorization"),
            Some(&"Bearer token123".to_string())
        );
    }

    #[test]
    fn test_parse_with_variables() {
        let content = r#"
@baseUrl = https://api.example.com
@token = abc123

GET {{baseUrl}}/users
Authorization: Bearer {{token}}

###
"#;

        let mut parser = HttpFileParser::new();
        let result = parser.parse_content(content).unwrap();

        assert_eq!(
            result.variables.get("baseUrl"),
            Some(&"https://api.example.com".to_string())
        );
        assert_eq!(result.variables.get("token"), Some(&"abc123".to_string()));

        let request = &result.requests[0];
        assert_eq!(request.url, "https://api.example.com/users");
        assert_eq!(
            request.headers.get("Authorization"),
            Some(&"Bearer abc123".to_string())
        );
    }

    #[test]
    fn test_parse_post_with_body() {
        let content = r#"
POST https://api.example.com/users
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com"
}

###
"#;

        let mut parser = HttpFileParser::new();
        let result = parser.parse_content(content).unwrap();

        let request = &result.requests[0];
        assert_eq!(request.method, "POST");
        assert!(request.body.is_some());
        assert!(request.body.as_ref().unwrap().contains("John Doe"));
    }

    #[test]
    fn test_parse_multiple_requests() {
        let content = r#"
# @name Get Users
GET https://api.example.com/users

###

# @name Create User
POST https://api.example.com/users
Content-Type: application/json

{
  "name": "Jane Doe"
}

###
"#;

        let mut parser = HttpFileParser::new();
        let result = parser.parse_content(content).unwrap();

        assert_eq!(result.requests.len(), 2);
        assert_eq!(result.requests[0].name, Some("Get Users".to_string()));
        assert_eq!(result.requests[1].name, Some("Create User".to_string()));
    }

    #[test]
    fn test_variable_substitution() {
        let parser = HttpFileParser::new();
        let mut variables = HashMap::new();
        variables.insert("host".to_string(), "api.example.com".to_string());
        variables.insert("port".to_string(), "8080".to_string());

        let result = parser
            .substitute_variables("https://{{host}}:{{port}}/api", &variables)
            .unwrap();
        assert_eq!(result, "https://api.example.com:8080/api");
    }

    #[test]
    fn test_undefined_variable() {
        let parser = HttpFileParser::new();
        let variables = HashMap::new();

        let result = parser.substitute_variables("{{undefined}}", &variables);
        assert!(result.is_err());
    }
}

