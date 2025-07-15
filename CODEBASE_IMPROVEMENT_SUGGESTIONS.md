# Saltybox Codebase Improvement Suggestions

## Overview
Saltybox is a well-structured Go application for file encryption with passphrases. The codebase demonstrates good practices with clean separation of concerns, proper error handling, and solid cryptographic implementation. However, there are several areas where improvements can enhance maintainability, security, user experience, and code quality.

## Current Strengths
- ✅ Clean package structure with clear separation of concerns
- ✅ Proper use of established cryptographic libraries (scrypt, NaCl)
- ✅ Comprehensive error handling with context
- ✅ Good test coverage across packages
- ✅ CI/CD pipeline with multiple Go versions
- ✅ Code quality tools (golangci-lint) configured
- ✅ Atomic file operations for safety
- ✅ Proper versioning and backwards compatibility

## Critical Improvements

### 1. **Security Enhancements**

#### Memory Security
- **Problem**: Passphrases are stored in Go strings, which are immutable and may remain in memory
- **Solution**: 
  - Use byte slices instead of strings for passphrases
  - Implement explicit memory zeroing: `for i := range passphrase { passphrase[i] = 0 }`
  - Consider using `golang.org/x/crypto/ssh/terminal` patterns for secure memory handling

#### Cryptographic Parameter Updates
- **Problem**: scrypt parameters (N=32768) are from 2009, may be insufficient for modern threats
- **Solution**: Update scrypt parameters to modern recommendations:
  - N = 1048576 (2^20) for better security
  - Add configuration option for custom parameters
  - Document performance vs security trade-offs

#### Side-Channel Attack Mitigation
- **Problem**: No protection against timing attacks during decryption
- **Solution**: Implement constant-time operations where possible
- Consider rate limiting for CLI usage

### 2. **Code Quality & Architecture**

#### Error Handling Improvements
```go
// Current pattern
return fmt.Errorf("failed to decrypt: %w", err)

// Suggested improvement with custom error types
type DecryptionError struct {
    Cause error
    IsAuthFailure bool
}

func (e *DecryptionError) Error() string {
    if e.IsAuthFailure {
        return "decryption failed: invalid passphrase or corrupted data"
    }
    return fmt.Sprintf("decryption failed: %v", e.Cause)
}
```

#### Input Validation
- **Problem**: Limited input validation for file paths and content
- **Solution**: Add comprehensive validation:
  - File size limits (prevent memory exhaustion)
  - Path traversal protection
  - Content type validation for binary vs text files

#### Dependency Management
- **Problem**: Direct dependency on specific versions
- **Solution**: 
  - Add dependency vulnerability scanning
  - Consider using Go workspaces for better dependency management
  - Document security update procedures

### 3. **User Experience Improvements**

#### CLI Interface Enhancements
- **Problem**: Limited CLI options and feedback
- **Solution**:
  - Add progress bars for large files
  - Verbose/quiet mode options
  - Better error messages with actionable suggestions
  - Add `--version` flag that shows actual version (currently shows "unknown")

#### Configuration Management
- **Problem**: No configuration file support
- **Solution**:
  - Add support for `.saltybox.yml` configuration
  - Environment variable support
  - Default encryption parameters configuration

#### File Format Improvements
- **Problem**: Limited metadata in encrypted files
- **Solution**:
  - Add optional metadata (creation time, original filename)
  - Implement file integrity verification
  - Consider adding compression option

### 4. **Testing & Quality Assurance**

#### Test Coverage Expansion
- **Problem**: Missing integration tests and edge cases
- **Solution**:
  - Add benchmarks for performance regression detection
  - Test with various file sizes (empty, large files)
  - Add fuzz testing for crypto functions
  - Property-based testing for encrypt/decrypt cycles

#### Security Testing
- **Problem**: No security-focused tests
- **Solution**:
  - Add tests for timing attack resistance
  - Memory usage tests
  - Cryptographic parameter validation tests

### 5. **Documentation & Maintenance**

#### API Documentation
- **Problem**: Limited internal documentation
- **Solution**:
  - Add comprehensive godoc comments
  - Document cryptographic design decisions
  - Add architecture decision records (ADRs)

#### Security Documentation
- **Problem**: Crypto disclaimer is generic
- **Solution**:
  - Add threat model documentation
  - Document security assumptions
  - Add cryptographic audit trail

### 6. **Performance & Scalability**

#### Memory Usage Optimization
- **Problem**: Entire file loaded into memory
- **Solution**:
  - Implement streaming encryption for large files
  - Add memory usage limits
  - Consider chunked processing

#### Build & Distribution
- **Problem**: No official binary releases
- **Solution**:
  - Add goreleaser configuration for automated releases
  - Cross-platform build verification
  - Add reproducible builds

## Specific Code Improvements

### 1. **Enhanced Error Types**
```go
// In secretcrypt/errors.go
type CryptError struct {
    Op   string
    Err  error
    Type ErrorType
}

type ErrorType int

const (
    ErrInvalidInput ErrorType = iota
    ErrBadPassphrase
    ErrCorrupted
    ErrMemory
)
```

### 2. **Secure Memory Management**
```go
// In preader/secure.go
type SecureBytes []byte

func (s *SecureBytes) Clear() {
    if s != nil {
        for i := range *s {
            (*s)[i] = 0
        }
    }
}

func (s *SecureBytes) String() string {
    return string(*s)
}
```

### 3. **Configuration Management**
```go
// In config/config.go
type Config struct {
    ScryptN int `yaml:"scrypt_n"`
    ScryptR int `yaml:"scrypt_r"`
    ScryptP int `yaml:"scrypt_p"`
    MaxFileSize int64 `yaml:"max_file_size"`
}

func LoadConfig() (*Config, error) {
    // Load from ~/.saltybox.yml, env vars, etc.
}
```

### 4. **Streaming Interface**
```go
// In secretcrypt/stream.go
type StreamEncryptor struct {
    writer io.Writer
    key    *[32]byte
}

func NewStreamEncryptor(w io.Writer, passphrase string) (*StreamEncryptor, error) {
    // Implementation for streaming encryption
}
```

## Implementation Priority

### Phase 1 (High Priority)
1. Memory security improvements
2. Enhanced error handling
3. Input validation
4. Version flag implementation

### Phase 2 (Medium Priority)
1. Configuration management
2. CLI UX improvements
3. Extended testing
4. Documentation updates

### Phase 3 (Future Enhancements)
1. Streaming encryption
2. Performance optimizations
3. Advanced features (metadata, compression)
4. Security audit integration

## Conclusion

The Saltybox codebase is solid and demonstrates good engineering practices. The suggested improvements focus on enhancing security, usability, and maintainability while preserving the tool's simplicity and reliability. The modular architecture makes these improvements feasible to implement incrementally.

Key areas requiring immediate attention:
- Memory security for passphrase handling
- Enhanced error reporting
- Input validation and security hardening
- Improved user experience

These improvements would transform Saltybox from a good tool into an excellent, production-ready encryption utility suitable for broader adoption.