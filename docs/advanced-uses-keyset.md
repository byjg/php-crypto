---
sidebar_position: 1
---

# Advanced uses of KeySet class

## Get the key and iv dynamically

The KeySet class can provide the dynamic key for your encryption.

```php title="Getting dynamic key and IV"
// Create a KeySet with your key seed
$keys = new \ByJG\Crypto\KeySet([
    // 2-255 entries of 32 bytes each
    '14dca647bcc087f67b1528cea11094838f5bd2276a08dcabc491c1823afc51dd',
    '9cc0fd22a3dc2fb3d444e0721e5d02f5c39f9d6b7c41c010a28e06e861f54c8b',
    // ... more keys
]);

// Assuming $algorithm is a valid OpenSSL cipher method (e.g., 'aes-256-cbc')
list($key, $iv, $header) = $keys->getKeyAndIv($algorithm);
echo base64_encode($key) . "\n";
echo base64_encode($iv) . "\n";
echo base64_encode($header) . "\n";
```

The `getKeyAndIv()` method returns a list with the key, the IV and the header.
The key and the IV have the lengths the algorithm takes.

The header can be used to restore the key and the IV later.

:::info
This key is the *master key*. `OpenSSLCrypto::encrypt()` does not encrypt with it directly: it
encrypts with the first bytes of `SHA-256(master key + "encryption")` and authenticates with
`SHA-256(master key + "authentication")`. See [Interoperability](interoperability.md).
:::

## Restore the key and iv

With the header you can restore the key and iv later. This is useful when you need to decrypt data that was encrypted with a specific key and IV.

```php title="Restoring key and IV from header"
// Create a KeySet with the same key seed used for encryption
$keys = new \ByJG\Crypto\KeySet([
    // 2-255 entries of 32 bytes each
    '14dca647bcc087f67b1528cea11094838f5bd2276a08dcabc491c1823afc51dd',
    '9cc0fd22a3dc2fb3d444e0721e5d02f5c39f9d6b7c41c010a28e06e861f54c8b',
    // ... more keys
]);

// Assuming $algorithm is the same cipher method used for encryption
// and $header is the header returned by getKeyAndIv()
list($key, $iv) = $keys->restoreKeyAndIv($algorithm, $header);
echo base64_encode($key) . "\n";
echo base64_encode($iv) . "\n";
```

A header that `getKeyAndIv()` could not have produced for this key seed — the wrong size, an entry
that does not exist, an offset past the end of the entry — throws `InvalidArgumentException`.

## Decrypt using the key and iv

`decryptWithKey()` decrypts raw cipher output with exactly the key and the IV you pass. It does
not read a header and does not check an HMAC.

To use it on the output of `encrypt()`, split the parts and derive the encryption key from the
master key:

```php title="Decrypting with key and IV"
$object = new \ByJG\Crypto\OpenSSLCrypto($algorithm, $keys);
$encrypted = $object->encrypt('my text');

list($hmac, $payload, $header, $cipherText) = $object->splitEncryptedText($encrypted);
list($key, $iv) = $keys->restoreKeyAndIv($algorithm, $header);

$encryptionKey = substr(hash('sha256', $key . 'encryption', true), 0, $keys->getKeyLength($algorithm));
echo $object->decryptWithKey($cipherText, $encryptionKey, $iv) . "\n"; // my text
```

Prefer `decrypt()`, which does all of this and verifies the HMAC first.
