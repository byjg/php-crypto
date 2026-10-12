# Changelog - Version 7.0

> **Status: in development.** This document tracks changes landing on the `7.0` branch.
> Nothing here is released yet, and the contents may still change.

## Breaking Changes

- **The key length is the one the cipher takes.** `KeySet::getKeyLength()` guessed it from the
  cipher name; it now asks OpenSSL (`openssl_cipher_key_length()`). The key derived for a cipher
  the guess got wrong changes, so **data encrypted with one of those ciphers on 6.x cannot be
  decrypted on 7.0**. Decrypt it with 6.x and encrypt it again.

  | Cipher | 6.x | 7.0 |
  |---|---|---|
  | `des-ede3-*` | 16 bytes | 24 bytes |
  | `chacha20` | 24 bytes | 32 bytes |
  | `bf-*` | 24 bytes | 16 bytes |

  AES, ARIA, Camellia, SM4 and `des-ede-*` already had the right length and are not affected. Any
  other cipher without `-128`, `-192` or `-256` in its name was given 24 bytes; check it with
  `openssl_cipher_key_length()`.
- `KeySet::getKeyLength()` throws `InvalidArgumentException` for a cipher OpenSSL does not know.
- `KeySet::restoreKeyAndIv()` throws `InvalidArgumentException` for a header that is not 4 bytes
  long or that points outside the key set.
- `KeySet` rejects an entry that is not 64 hexadecimal characters. A 64-character entry with other
  characters was accepted with a warning.

## Bug Fixes

- `OpenSSLCrypto::decrypt()` rejects a header that points outside the key set with
  `Authentication failed`, like any other tampered data. It used to raise "Undefined array key"
  and a `hex2bin()` deprecation before the HMAC check rejected it.
- The scripts in `examples/` load `vendor/autoload.php` from the right directory.

## Documentation

- [Interoperability](docs/interoperability.md) was rewritten against the current format. The
  CryptoJS sections were written for the 3-byte header used before 6.0 and derived the keys from the
  hexadecimal text of the master key; neither worked. Every example there was run: the OpenSSL
  command line and CryptoJS both produce data `decrypt()` reads.
- [Keyless Exchange](docs/keyless-exchange.md): the header ranges and the number of key/IV
  combinations are the real ones (435,200 for the default key seed with AES, not "millions"), and
  the "Forward Secrecy" section is gone — the library does not provide it.
- [Advanced uses of KeySet](docs/advanced-uses-keyset.md): `decryptWithKey()` on the output of
  `encrypt()` needs the derived encryption key, not the key `restoreKeyAndIv()` returns.
- The README example did not parse.

## Requirements

- PHP 8.3, 8.4, 8.5 and 8.6 are now supported: `"php": ">=8.3 <8.7"`.
  The previous `<8.6` upper bound excluded PHP 8.6, since `<8.6` is exclusive.

## Toolchain

- PHPUnit updated to `^12.5`.
- Psalm is installed as `psalm/phar` (`^6.16`) instead of `vimeo/psalm`.

  `vimeo/psalm` lists the PHP versions it supports and no published release includes
  8.6, so as a dev dependency it made `composer install` fail on the 8.6 build job
  before any test ran. `psalm/phar` requires only `php ^8.2` and bundles its own
  dependencies, so it installs on every PHP version in the matrix and cannot conflict
  with the project's. Psalm itself still refuses to *run* on 8.6, which is why the
  Psalm job uses 8.5. `composer psalm` runs it.

  PHPUnit 13 is deliberately **not** used. It requires PHP `>=8.4.1`, which would
  break the 8.3 floor.

## Continuous Integration

- The build matrix now includes PHP 8.6.
- The Psalm job now runs on PHP 8.5. Psalm declares
  `~8.1.31 || ~8.2.27 || ~8.3.16 || ~8.4.3 || ~8.5.0` and therefore does not run on
  PHP 8.6.

## Housekeeping

- `phpunit.xml.dist` renamed to `phpunit.xml`.
