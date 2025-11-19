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

The `getKeyAndIv()` method will return a list with the key, the iv and the header. 
The key and iv is based on the Key and Iv Length of the algorithm.

The header can be used to restore the key and iv later. 

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

## Decrypt using the key and iv

```php title="Decrypting with key and IV"
// Assuming $algorithm is a valid OpenSSL cipher method (e.g., 'aes-256-cbc')
// and $cipherText is the encrypted text without the header
$object = new \ByJG\Crypto\OpenSSLCrypto($algorithm, $keys);
echo $object->decryptWithKey($cipherText, $key, $iv) . "\n";
``` 
