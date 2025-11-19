---
sidebar_position: 3
---

# Keyless Exchange

One of the most innovative features of this library is the ability to exchange encrypted data without transmitting the actual encryption keys. This is achieved through a clever combination of a shared key seed and a minimal header.

## The Problem with Traditional Key Exchange

In traditional symmetric encryption, you face a critical challenge: how do you securely share the encryption key with the recipient? If you can securely share the key, why not just use that secure channel for the data itself?

Common solutions include:
- **Key Distribution Centers (KDC)**: Complex infrastructure
- **Asymmetric Encryption**: Performance overhead for key exchange
- **Pre-shared Keys**: Key management and rotation challenges

## The Keyless Exchange Solution

This library eliminates the key exchange problem by using a **key seed** that both parties share once (out of band), and then generating unique keys for each encryption operation.

### How It Works

#### 1. One-Time Key Seed Setup

Both the sender and receiver obtain the same key seed (2-255 entries of 32 bytes each):

```php title="One-time key seed setup (both parties)"
// Generate once, share securely out of band
$keySet = \ByJG\Crypto\KeySet::generateKeySet(32);

// Both parties must have the exact same key seed
$keys = new \ByJG\Crypto\KeySet($keySet);
```

:::tip
The key seed only needs to be shared **once** using a secure out-of-band method (e.g., during initial setup, via secure configuration management, or encrypted storage). After that, you can exchange unlimited encrypted messages without ever transmitting keys again.
:::

#### 2. Encryption with Dynamic Keys

Each time you encrypt data, a unique key and IV are generated:

```php title="Sender encrypts with dynamically generated keys"
$crypto = new \ByJG\Crypto\OpenSSLCrypto('aes-256-cbc', $keys);
$encrypted = $crypto->encrypt('Sensitive data');

// The encrypted string contains:
// - HMAC (32 bytes) for authentication
// - Header (4 bytes) - the "map" to reconstruct the key using scrolling window
// - Ciphertext (variable length)
//
// Note: The actual key and IV are NOT included!
```

#### 3. The Magic Header (4 bytes)

The header encodes:
- **Byte 1**: Index of the key seed entry for the encryption key (0-255)
- **Byte 2**: Offset for key extraction using 8-byte scrolling window (0-255)
- **Byte 3**: Index of the key seed entry for the IV (0-255)
- **Byte 4**: Offset for IV extraction using 8-byte scrolling window (0-255)

This compact header contains all the information needed to reconstruct the exact key and IV used for encryption using the scrolling window technique.

#### 4. Decryption Reconstructs Keys

The recipient can decrypt the data using only the encrypted payload and the shared key seed:

```php title="Receiver decrypts by reconstructing keys from header"
$crypto = new \ByJG\Crypto\OpenSSLCrypto('aes-256-cbc', $keys);
$decrypted = $crypto->decrypt($encrypted);

// Internally:
// 1. Extract header from encrypted payload
// 2. Use header to select the same key seed portions
// 3. Reconstruct the exact key and IV
// 4. Verify HMAC for authenticity
// 5. Decrypt the data
```

## Security Benefits

### 1. No Key Transmission

The encryption key is **never** transmitted over the network. Only the 4-byte header is sent, which is useless without the key seed.

### 2. Unique Keys Per Message

Each encryption operation uses different random portions of the key seed with the 8-byte scrolling window, providing automatic key rotation with millions of possible combinations.

### 3. Forward Secrecy

Even if one message is compromised, other messages remain secure because they use different keys.

### 4. Authentication

HMAC-SHA256 ensures data integrity and authenticity - any tampering is immediately detected.

## Example: Secure Message Exchange

```php title="Complete example of keyless exchange"
// === SETUP PHASE (one time) ===
// Party A and Party B both obtain the same key seed
$keySet = \ByJG\Crypto\KeySet::generateKeySet(32);
// (Key seed is shared securely out of band)

// === PARTY A (Sender) ===
$keysA = new \ByJG\Crypto\KeySet($keySet);
$cryptoA = new \ByJG\Crypto\OpenSSLCrypto('aes-256-cbc', $keysA);

$message = "Top secret information";
$encrypted = $cryptoA->encrypt($message);

// Party A sends $encrypted over any channel (email, HTTP, database, etc.)
// No keys are transmitted!

// === PARTY B (Receiver) ===
$keysB = new \ByJG\Crypto\KeySet($keySet);
$cryptoB = new \ByJG\Crypto\OpenSSLCrypto('aes-256-cbc', $keysB);

$decrypted = $cryptoB->decrypt($encrypted);
// Result: "Top secret information"
```

## Understanding the Header Format

For those interested in the technical details:

```
Header Structure (4 bytes):
┌──────────────┬────────────────┬──────────────┬────────────────┐
│  Byte 1 (A)  │ Byte 2 (OffA)  │  Byte 3 (B)  │ Byte 4 (OffB)  │
└──────────────┴────────────────┴──────────────┴────────────────┘

Byte 1: Key seed entry index A for encryption key (0-255)
Byte 2: Offset for key extraction - scrolling window position (0-24)
Byte 3: Key seed entry index B for IV (0-255)
Byte 4: Offset for IV extraction - scrolling window position (0-24)
```

**Scrolling Window Mechanism:**

Each 32-byte key seed entry can provide key material using an 8-byte scrolling window:
- Window size: 8 bytes
- Possible positions: 0-24 (offsets where the 8-byte window fits)
- Window extracts: 8 consecutive bytes starting at the offset

For algorithms needing more than 8 bytes (e.g., AES-256 needs 32 bytes), the library uses key derivation from the 8-byte window.

This encoding allows for:
- 2-255 possible key seed entries
- 25 possible window positions per entry (offsets 0-24)
- Independent offsets for key and IV
- Total combinations: Up to 255 × 25 × 255 × 25 = **~40 million** possible key/IV pairs from a single key seed!

## Best Practices

1. **Protect the Key Seed**: The key seed is the root of trust. Store it securely (encrypted configuration, secrets management, etc.)

2. **Use Sufficient Entries**: More key seed entries = more possible key combinations. 32 entries is recommended.

3. **Key Seed Rotation**: Periodically rotate the key seed for long-term security.

4. **Secure Initial Exchange**: The key seed must be exchanged securely during initial setup.

## Comparison with Other Approaches

| Approach              | Key Exchange  | Performance            | Complexity            |
|-----------------------|---------------|------------------------|-----------------------|
| **Keyless Exchange**  | One-time seed | Fast (symmetric only)  | Low                   |
| Asymmetric (RSA/EC)   | Per session   | Slow (hybrid crypto)   | Medium                |
| Pre-shared Keys       | One-time key  | Fast                   | High (key management) |
| Diffie-Hellman        | Per session   | Medium                 | Medium                |

The keyless exchange approach combines the performance of symmetric encryption with the convenience of not needing per-message key exchange.
