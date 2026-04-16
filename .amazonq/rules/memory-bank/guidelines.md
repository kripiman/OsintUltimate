# OsintUltimate V14.1 - Development Guidelines

## Code Quality Standards

### Error Handling Patterns
- **Primary Pattern**: Use `anyhow::Result<T>` for all fallible operations
- **Context Addition**: Always add meaningful context to errors using `.context()` or `?` operator
- **Input Validation**: Validate all external inputs and file paths to prevent security issues
- **Path Traversal Protection**: Check for `..` components in file paths before processing
- **Graceful Degradation**: Handle missing or invalid data gracefully with default values

### Async Programming Standards
- **Tokio Runtime**: All async operations use Tokio runtime with full feature set
- **Async File I/O**: Use `tokio::fs` for all file operations
- **Stream Processing**: Use `BufReader` with `lines()` for efficient line-by-line processing
- **Async Traits**: Use `async-trait` crate for trait definitions with async methods
- **Resource Management**: Properly handle async resource cleanup and cancellation

### Memory Safety & Performance
- **Zero-Copy Operations**: Minimize unnecessary string allocations and cloning
- **Efficient Collections**: Use `Vec::with_capacity()` when size is known
- **String Handling**: Use `String::from()` for static strings, avoid unnecessary `to_string()`
- **HTML Escaping**: Always escape user input in HTML contexts using `html_escape::encode_safe()`
- **JSON Serialization**: Use `serde_json` with proper error handling for all JSON operations

## Structural Conventions

### Module Organization
- **Hierarchical Structure**: Organize code by functional domain (core/, plugins/, utils/, models/)
- **Plugin Architecture**: Each plugin in separate module with consistent interface
- **Capability Layers**: Group functionality by operational phases (0-5)
- **Clear Separation**: Separate concerns between data models, business logic, and presentation

### Naming Conventions
- **Constants**: Use `SCREAMING_SNAKE_CASE` for all constants
- **Plugin Names**: Use descriptive names ending with "Scanner" (e.g., `PLUGIN_NUCLEI: "NucleiScanner"`)
- **Finding IDs**: Use hyphenated uppercase format (e.g., `FINDING_SQL_INJECTION: "SQL-INJECTION"`)
- **Struct Names**: Use `PascalCase` for all struct and enum names
- **Function Names**: Use `snake_case` for all function and method names

### Documentation Standards
- **Module Comments**: Brief comment describing module purpose at top of each file
- **Public APIs**: Document all public functions and structs with rustdoc comments
- **Code Comments**: Use inline comments sparingly, prefer self-documenting code
- **TODO/FIXME**: Use structured comments for future improvements

## Semantic Patterns

### Data Structure Patterns
- **Serde Integration**: All data structures use `#[derive(Serialize, Deserialize)]` where appropriate
- **Default Implementations**: Provide `Default` implementations for configuration structs
- **Builder Pattern**: Use for complex configuration objects
- **Type Safety**: Use enums for finite state representations (e.g., `InfrastructureType`, `Severity`)

### Template and Rendering Patterns
- **Handlebars Templates**: Use Handlebars for all HTML template rendering
- **Template Security**: Enable strict mode with `reg.set_strict_mode(true)`
- **Custom Helpers**: Register custom helpers for complex template logic
- **Template Embedding**: Embed templates as string constants for single-file distribution

### System Integration Patterns
- **Hardware Detection**: Use `sysinfo` crate for system information gathering
- **Resource Classification**: Classify system capabilities into discrete tiers
- **Adaptive Behavior**: Adjust functionality based on detected hardware capabilities
- **Cross-Platform Support**: Write platform-agnostic code where possible

## Internal API Usage Patterns

### File I/O Operations
```rust
// Standard async file reading pattern
let file = File::open(path).await?;
let mut reader = BufReader::new(file).lines();
while let Some(line) = reader.next_line().await? {
    // Process line
}
```

### Error Context Addition
```rust
// Always add meaningful context to errors
let result = operation()
    .await
    .context("Failed to perform critical operation")?;
```

### HTML Template Rendering
```rust
// Standard template rendering pattern
let mut reg = Handlebars::new();
reg.set_strict_mode(true);
reg.register_helper("custom_helper", Box::new(helper_function));
let rendered = reg.render_template(TEMPLATE, &view_model)?;
```

### Path Validation
```rust
// Security-first path validation
let path = std::path::Path::new(user_input);
if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
    anyhow::bail!("Invalid path: Traversal (..) detected");
}
```

## Frequently Used Code Idioms

### Conditional Processing
- **Early Returns**: Use early returns for error conditions and validation
- **Option Handling**: Use `unwrap_or_default()` for safe option handling
- **Result Chaining**: Chain operations with `?` operator for clean error propagation

### String Processing
- **HTML Escaping**: Always escape user content: `html_escape::encode_safe(&input).to_string()`
- **JSON Parsing**: Use structured error handling for JSON operations
- **Template Variables**: Use descriptive variable names in templates

### Collection Operations
- **Iteration**: Prefer iterator methods over manual loops
- **Filtering**: Use `filter()` and `map()` for data transformation
- **Aggregation**: Use `fold()` or `reduce()` for accumulation operations

## Security and OPSEC Patterns

### Input Validation
- **Path Traversal**: Always check for `..` components in file paths
- **HTML Injection**: Escape all user input in HTML contexts
- **Command Injection**: Validate and sanitize all external command inputs
- **Resource Limits**: Implement bounds checking for resource-intensive operations

### Data Sanitization
- **Sensitive Data**: Scrub sensitive information from logs and outputs
- **Error Messages**: Avoid exposing internal system details in error messages
- **Template Security**: Use strict mode in template engines
- **JSON Security**: Validate JSON structure before processing

## Testing and Quality Assurance

### Code Organization for Testing
- **Testable Functions**: Write pure functions that are easy to test
- **Dependency Injection**: Use trait objects for external dependencies
- **Mock-Friendly Design**: Structure code to allow easy mocking
- **Integration Points**: Clearly define boundaries between components

### Performance Considerations
- **Async Efficiency**: Use appropriate async patterns for I/O-bound operations
- **Memory Usage**: Monitor memory allocation patterns in hot paths
- **Resource Cleanup**: Ensure proper cleanup of system resources
- **Caching Strategy**: Implement appropriate caching for expensive operations

## Plugin Development Standards

### Plugin Interface Consistency
- **Standard Traits**: Implement common traits for all plugins
- **Error Handling**: Use consistent error handling across all plugins
- **Configuration**: Use structured configuration objects
- **Logging**: Implement consistent logging patterns

### Plugin Registration
- **Constant Definitions**: Define plugin constants in `models/constants.rs`
- **Naming Convention**: Follow established naming patterns
- **Module Structure**: Organize plugin code in appropriate subdirectories
- **Documentation**: Document plugin capabilities and requirements