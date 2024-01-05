# Interoperability

We can generate use third party libraries to encrypt some data and use this library to decypher it.

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
$object = new OpenSSLCrypto($algorithm, \ByJG\Crypto\KeySet::generateKeySet());
echo $crypto->decryptWithKey(base64_decode($cypher), $key, $iv) . "\n";
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
  
  // This is the cypher to be used in PHP
  console.log(encrypted.ciphertext.toString());
</script>
</html>
```
