# Contributing to Kassadin

Thank you for your interest in contributing to Kassadin! We're building the future of Cardano nodes, and we'd love your help.

## 🎯 Our Development Philosophy

1. **No TODOs**: We complete what we start
2. **Production Quality**: Every line of code is written with production intent
3. **Test Everything**: Comprehensive tests for all functionality
4. **Clear Communication**: Document decisions and rationale

## 🚀 Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/yourusername/kassadin.git
   cd kassadin
   ```

2. **Set up your environment**
   ```bash
   # Install Zig 0.13.0
   # Install libsodium
   zig build test  # Ensure tests pass
   ```

3. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 💻 Development Process

### Before You Code

1. Check existing issues and discussions
2. For major changes, open an issue first to discuss
3. Ensure your idea aligns with project goals

### While Coding

1. **Follow Zig idioms**: Use Zig's standard patterns
2. **Write tests first**: TDD helps catch issues early
3. **Document your code**: Clear comments for complex logic
4. **Handle errors explicitly**: No silent failures
5. **Check performance**: Profile if touching hot paths

### Code Style

```bash
# Format your code
zig fmt src/

# Run tests
zig build test

# Check for common issues
zig build check
```

### Commit Messages

Follow conventional commits:
```
feat: add VRF verification
fix: correct UTXO validation logic
docs: update consensus documentation
test: add chain selection tests
perf: optimize block processing
```

## 🧪 Testing

Every feature needs tests:

```zig
test "YourFeature.basicFunctionality" {
    // Arrange
    const input = ...;
    
    // Act
    const result = try yourFunction(input);
    
    // Assert
    try std.testing.expectEqual(expected, result);
}
```

## 📝 Pull Request Process

1. **Update tests**: Ensure all tests pass
2. **Update documentation**: Keep docs in sync
3. **Clean commits**: Squash if needed
4. **Clear description**: Explain what and why
5. **Link issues**: Reference related issues

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Performance improvement
- [ ] Documentation update

## Testing
- [ ] All tests pass
- [ ] Added new tests
- [ ] Manually tested

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings
```

## 🏗️ Architecture Guidelines

### Module Structure

```zig
// Public API at top
pub const YourType = struct {
    // Public fields first
    pub field: Type,
    
    // Private fields
    private_field: Type,
    
    // Public methods
    pub fn publicMethod(self: *YourType) !void {
        // Implementation
    }
    
    // Private methods
    fn privateHelper(self: *YourType) void {
        // Implementation
    }
};

// Tests at bottom
test "YourType.functionality" {
    // Test implementation
}
```

### Error Handling

```zig
// Define specific errors
const YourError = error{
    InvalidInput,
    ResourceExhausted,
    ProtocolViolation,
};

// Return errors explicitly
pub fn process(data: []const u8) YourError!Result {
    if (data.len == 0) return error.InvalidInput;
    // ...
}
```

## 🎯 Areas of Focus

### High Priority
- Testnet connectivity
- Performance optimization
- Security hardening
- Documentation

### Good First Issues
- Add more tests
- Improve error messages
- Documentation fixes
- Code cleanup

### Advanced
- Protocol improvements
- Consensus optimization
- New features
- Architecture changes

## 🤝 Community

- **Discord**: Join our Discord for discussions
- **Issues**: Check GitHub issues for tasks
- **Discussions**: Use GitHub Discussions for ideas

## ⚖️ License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

All contributors will be recognized in our README and release notes.

---

**Thank you for contributing to Kassadin! Together, we're building something amazing.**