# Interoperability

We can use third party libraries to encrypt some data and use this library to decrypt it.

## OpenSSL command line

The OpenSSL command line can be used to encrypt some data. The command line is:

```bash
PASSWORD=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)
echo "this is a test" | openssl aes-256-cbc -e -a -K $PASSWORD -iv $IV
```

and then

```php
<?php
// Assuming $algorithm is 'aes-256-cbc', $cipherText is the base64-encoded encrypted text,
// and $key and $iv are the values used for encryption
$object = new \ByJG\Crypto\OpenSSLCrypto($algorithm, \ByJG\Crypto\KeySet::generateKeySet());
echo $object->decryptWithKey(base64_decode($cipherText), hex2bin($PASSWORD), hex2bin($IV)) . "\n";
```

## JavaScript CryptoJS

The CryptoJS library can be used to encrypt some data. The code is:

```html
<html>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/aes.js"></script>
<script>
  var myPassword = "myPassword";

  // Can be obtained from KeySet::getKeyAndIv() 
  var key = "OgCSEZDInyGgQtnXMA9dNrwYd99UJh0L9kk/Q/sFX8g=";
  var iv = "Ww4z5IE0Vcp9uYF5mvaqQA==";
  var header = "xQUt";

  // PROCESS
  var encrypted = CryptoJS.AES.encrypt(
    myPassword,
    CryptoJS.enc.Base64.parse(key),
    {
      iv: CryptoJS.enc.Base64.parse(iv),
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    }
  );

  // This is the cipher to be used in PHP
  console.log(encrypted.ciphertext.toString());
</script>
</html>
```

Then in PHP, you can decrypt the data using:

```php
<?php
// Assuming $algorithm is 'aes-256-cbc', $cipherText is the encrypted text from JavaScript,
// and $key and $iv are the same values used in JavaScript
$object = new \ByJG\Crypto\OpenSSLCrypto($algorithm, \ByJG\Crypto\KeySet::generateKeySet());
echo $object->decryptWithKey($cipherText, base64_decode($key), base64_decode($iv)) . "\n";
```
