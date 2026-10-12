# Changelog - Version 6.0

## Overview

Version 6.0 represents a major evolution of the php-crypto library, introducing significant security enhancements, a revolutionary keyless exchange mechanism, and modern PHP support. This release focuses on cryptographic best practices, authenticated encryption, and improved interoperability.

---

## New Features

### 1. Keyless Exchange Mechanism
- **Innovative encryption approach** using key seeds instead of traditional key exchange
- **Scrolling window technique** with 4-byte headers to dynamically generate encryption keys
- Each encryption operation uses unique keys without transmitting actual keys
- Up to **~40 million possible key/IV combinations** from a single key seed
- Comprehensive documentation explaining the keyless exchange concept
- Examples demonstrating secure message exchange without key transmission

### 2. HMAC-Based Authenticated Encryption
- **HMAC-SHA256 authentication** for tamper detection and data integrity
- **Encrypt-then-MAC pattern** following industry security standards
- **Constant-time MAC verification** to prevent timing attacks
- **Protection against padding oracle attacks**
- Comprehensive security improvements making the library production-ready

### 3. Enhanced Scrolling Window Implementation
- **4-byte header format** encoding key seed indices and extraction offsets
- 8-byte scrolling window extracting portions from 32-byte key seed entries
- 25 possible positions per entry (offsets 0-24)
- Proper key derivation for algorithms requiring different key lengths
- Format: `HMAC(32 bytes) + Header(4 bytes) + Ciphertext(variable)`

### 4. JavaScript Interoperability
- Complete JavaScript implementation for browser-based encryption
- Interactive test suite (`examples/js/test.html`) for cross-platform testing
- PHP verification scripts (`examples/js/verify.php`, `examples/js/test.php`)
- Full documentation for implementing the encryption format in other languages
- Support for both legacy and authenticated encryption formats

### 5. Enhanced KeySet Class
- Improved key seed generation with `KeySet::generateKeySet()`
- Support for 2-255 key seed entries of 32 bytes each
- Better validation and error handling
- Advanced usage examples and documentation

### 6. Security Demonstration
- New `examples/security_demo.php` showcasing cryptographic features
- Demonstrates encryption/decryption workflow
- Tampering detection examples
- Algorithm compatibility testing
- Format analysis and security improvements summary

### 7. Comprehensive Documentation
- **Keyless Exchange Guide** (`docs/keyless-exchange.md`) - detailed explanation of the innovative approach
- **Advanced KeySet Usage** (`docs/advanced-uses-keyset.md`) - advanced patterns and examples
- **Interoperability Guide** (`docs/interoperability.md`) - cross-platform implementation details
- Security best practices and recommendations
- Migration guides and examples

### 8. PHP 8.4 and 8.5 Support
- Full compatibility with PHP 8.4
- Forward compatibility with PHP 8.5
- Use of modern PHP features and attributes
- `#[Override]` attributes for better IDE support
- PHPUnit `#[DataProvider]` attributes replacing doc-comment syntax

### 9. Enhanced Testing and Quality Assurance
- PHPUnit 10/11 compatibility with modern XML schema
- Comprehensive test coverage for authenticated encryption
- Psalm static analysis integration with SARIF reporting
- GitHub CodeQL integration for security analysis
- Improved CI/CD workflows with multiple PHP versions

---

## Breaking Changes

| Aspect | Before (5.x) | After (6.0) | Description |
|--------|--------------|-------------|-------------|
| **PHP Version** | PHP >= 8.1 | PHP >= 8.3 | Dropped support for PHP 8.1 and 8.2 |
| **Encryption Format** | Legacy format without authentication | HMAC(32) + Header(4) + Ciphertext | New authenticated encryption format with HMAC-SHA256 |
| **Header Size** | Variable/undefined | 4 bytes (fixed) | Standardized 4-byte header with scrolling window offsets |
| **Key Extraction** | Direct key usage | 8-byte scrolling window | Dynamic key extraction using offsets (0-24 positions) |
| **Authentication** | None | HMAC-SHA256 required | All encrypted data now includes authentication tag |
| **PHPUnit** | v9.6 | v10.5 or v11.5 | Upgraded to modern PHPUnit versions |
| **Psalm** | Not included | v5.9 or v6.13+ | Added static analysis as standard |
| **Test DataProviders** | `@dataProvider` doc-comments | `#[DataProvider]` attributes | Modern PHP 8+ attribute syntax |
| **PHPUnit XML Schema** | Legacy `<filter>/<whitelist>` | `<source>/<include>` | PHPUnit 10/11 compatible configuration |
| **Decryption Behavior** | Returns decrypted data on invalid MAC | Throws `OpenSSLException` | Security enhancement - fails fast on tampering |

---

## Bug Fixes

- Fixed PHPUnit 10/11 compatibility issues with DataProvider methods
- Resolved Psalm static analysis errors and type issues
- Fixed constant-time comparison implementation for MAC verification
- Corrected key derivation for different encryption algorithms
- Fixed padding oracle vulnerability through authenticated encryption
- Resolved timing attack vulnerabilities with constant-time operations

---

## Migration Path from 5.x to 6.0

### Step 1: Update PHP Version

**Action Required:** Upgrade your PHP environment to 8.3 or higher.

```bash
# Check current PHP version
php -v

# Upgrade to PHP 8.3+ (method varies by OS)
# Ubuntu/Debian example:
sudo apt-get install php8.3
```

### Step 2: Update Dependencies

Update your `composer.json`:

```bash
composer require byjg/crypto:^6.0
composer update
```

### Step 3: Understand Encryption Format Changes

**Important:** Version 6.0 uses a new authenticated encryption format that is **not compatible** with data encrypted by version 5.x.

#### Option A: Fresh Start (Recommended for New Projects)
Simply use version 6.0 for all new encryption operations. The library will automatically use the secure authenticated format.

```php
// Version 6.0 - New code works out of the box
$keySet = new \ByJG\Crypto\KeySet([/* your keys */]);
$crypto = new \ByJG\Crypto\OpenSSLCrypto('aes-256-cbc', $keySet);

$encrypted = $crypto->encrypt('My data');  // Uses new authenticated format
$decrypted = $crypto->decrypt($encrypted);  // Automatically handles new format
```

#### Option B: Migration Strategy for Existing Encrypted Data

If you have data encrypted with version 5.x that needs to be preserved:

**Migration Steps:**

1. **Decrypt all existing data with version 5.x** before upgrading:
   ```php
   // Using version 5.x
   $oldCrypto = new \ByJG\Crypto\OpenSSLCrypto('aes-256-cbc', $oldKeySet);
   $decrypted = $oldCrypto->decrypt($legacyEncryptedData);

   // Store decrypted data temporarily or re-encrypt immediately
   ```

2. **Upgrade to version 6.0**
   ```bash
   composer require byjg/crypto:^6.0
   ```

3. **Re-encrypt data with version 6.0**:
   ```php
   // Using version 6.0
   $newCrypto = new \ByJG\Crypto\OpenSSLCrypto('aes-256-cbc', $newKeySet);
   $newEncrypted = $newCrypto->encrypt($decrypted);

   // Store the newly encrypted data
   ```

**Alternative: Dual-Version Migration**

For systems that cannot decrypt all data at once:

1. Keep version 5.x available in a separate namespace or service
2. Decrypt with 5.x when needed, then re-encrypt with 6.0
3. Gradually migrate all encrypted data over time
4. Track which format each piece of data uses (e.g., database flag)

### Step 4: Update PHPUnit Configuration (If Running Tests)

Update `phpunit.xml.dist` to PHPUnit 10/11 format:

**Before (5.x):**
```xml
<filter>
    <whitelist processUncoveredFilesFromWhitelist="true">
        <directory suffix=".php">src</directory>
    </whitelist>
</filter>
```

**After (6.0):**
```xml
<source>
    <include>
        <directory suffix=".php">src</directory>
    </include>
</source>
```

### Step 5: Update Test Code (If Applicable)

**Before (5.x):**
```php
/**
 * @dataProvider providerData
 */
public function testSomething($input, $expected) {
    // test code
}

public function providerData() {  // Non-static
    return [/* data */];
}
```

**After (6.0):**
```php
#[DataProvider('providerData')]
public function testSomething($input, $expected) {
    // test code
}

public static function providerData(): array {  // Must be static
    return [/* data */];
}
```

### Step 6: Verify Security Improvements

Run the security demonstration to verify the new features:

```bash
php examples/security_demo.php
```

Expected output should confirm:
- ✅ Encryption/decryption works correctly
- ✅ Tampering is detected and rejected
- ✅ HMAC authentication is functioning
- ✅ All security features are operational

### Step 7: Update Error Handling

Version 6.0 throws `OpenSSLException` when decryption fails (e.g., due to tampering):

```php
use ByJG\Crypto\OpenSSLException;

try {
    $decrypted = $crypto->decrypt($encrypted);
} catch (OpenSSLException $e) {
    // Handle decryption failure (tampering, wrong key, etc.)
    error_log("Decryption failed: " . $e->getMessage());
}
```

### Step 8: Review Documentation

Familiarize yourself with the new concepts:
- Read `docs/keyless-exchange.md` to understand the keyless exchange mechanism
- Review `docs/interoperability.md` if implementing cross-platform encryption
- Check `docs/advanced-uses-keyset.md` for advanced patterns

---

## Additional Changes

### Development Environment
- Added comprehensive VSCode debugging configurations (`.vscode/launch.json`)
- Removed deprecated Travis CI configuration
- Enhanced GitHub Actions workflows with PHP 8.4 and 8.5 support
- Added Psalm SARIF reporting for GitHub Security tab integration
- Improved `.gitignore` for modern development workflows

### Code Quality
- Full Psalm static analysis integration
- PHPUnit code coverage improvements
- Better type safety and strict typing
- Enhanced error messages and exception handling

### Examples and Documentation
- Interactive JavaScript test suite for browser testing
- Comprehensive security demonstration script
- Real-world usage examples
- Best practices and security recommendations

---

## Acknowledgments

This release represents a significant improvement in cryptographic security and usability. The keyless exchange mechanism and authenticated encryption make this library suitable for production use in security-sensitive applications.

**Security Notice:** Version 6.0 addresses several security concerns from previous versions. Users are strongly encouraged to upgrade and re-encrypt sensitive data using the new authenticated format.

---

## Resources

- [GitHub Repository](https://github.com/byjg/php-crypto)
- [Documentation](https://opensource.byjg.com)
- [Issue Tracker](https://github.com/byjg/php-crypto/issues)
- [Sponsor](https://github.com/sponsors/byjg)

---

**Release Date:** 2025
**License:** MIT
