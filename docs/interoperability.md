---
sidebar_position: 2
---

# Interoperability

Other tools can produce data this library decrypts, and decrypt what it produces, as long as they
follow the same format.

## The format

`encrypt()` returns `base64(HMAC + header + ciphertext)`:

| Part       | Size     | Content                                                                 |
|:-----------|:---------|:------------------------------------------------------------------------|
| HMAC       | 32 bytes | HMAC-SHA256 of `header + ciphertext`, with the authentication key       |
| Header     | 4 bytes  | Where in the key seed the key and the IV come from                      |
| Ciphertext | variable | The cipher's raw output, with the encryption key and the IV             |

`KeySet::getKeyAndIv()` returns a master key, the IV and the header. The two keys in the table are
derived from the master key:

- **encryption key**: the first bytes of `SHA-256(master key + "encryption")`, as many as the
  cipher's key takes (32 for `aes-256-cbc`);
- **authentication key**: the 32 bytes of `SHA-256(master key + "authentication")`.

The hash is taken over the raw bytes of the master key followed by the label, not over its
hexadecimal or Base64 text.

`decrypt()` reads the header, rebuilds the master key and the IV from the key seed, checks the HMAC
and only then decrypts. Anything that fails that check — a header that does not belong to the key
seed included — is rejected with `Authentication failed`.

## OpenSSL command line

### Decrypting what OpenSSL encrypted with its own key

When the data was encrypted with a key and an IV that did not come from a key seed, there is no
header and no HMAC. Use `decryptWithKey()` with the raw values:

```bash title="Encrypting with the OpenSSL CLI"
PASSWORD=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)
echo "this is a test" | openssl aes-256-cbc -e -a -K $PASSWORD -iv $IV
```

```php title="Decrypting it"
// $cipherText is the Base64 text printed above; $PASSWORD and $IV are the values used
$keys = new \ByJG\Crypto\KeySet(\ByJG\Crypto\KeySet::generateKeySet());
$object = new \ByJG\Crypto\OpenSSLCrypto('aes-256-cbc', $keys);
echo $object->decryptWithKey(base64_decode($cipherText), hex2bin($PASSWORD), hex2bin($IV));
```

The key seed is not used here: `decryptWithKey()` takes the key and the IV you give it. Nothing
authenticates this data.

### Producing the library's format with OpenSSL

To build something `decrypt()` accepts, the key and the IV have to come from the key seed. Ask
`KeySet` for them and derive the two keys:

```php title="export.php"
<?php
require "vendor/autoload.php";

$keys = new \ByJG\Crypto\KeySet([/* your key seed */]);
$algorithm = 'aes-256-cbc';

[$masterKey, $iv, $header] = $keys->getKeyAndIv($algorithm);

$encryptionKey = substr(hash('sha256', $masterKey . 'encryption', true), 0, $keys->getKeyLength($algorithm));
$authKey = hash('sha256', $masterKey . 'authentication', true);

echo "ENC_KEY=" . bin2hex($encryptionKey) . "\n";
echo "AUTH_KEY=" . bin2hex($authKey) . "\n";
echo "IV=" . bin2hex($iv) . "\n";
echo "HEADER=" . bin2hex($header) . "\n";
```

```bash title="Encrypting and authenticating with the OpenSSL CLI"
eval "$(php export.php)"

CIPHER=$(echo -n "this is a test" | openssl enc -aes-256-cbc -K $ENC_KEY -iv $IV | xxd -p | tr -d '\n')
HMAC=$(echo -n "$HEADER$CIPHER" | xxd -r -p \
    | openssl dgst -sha256 -mac HMAC -macopt hexkey:$AUTH_KEY -binary | xxd -p | tr -d '\n')

echo -n "$HMAC$HEADER$CIPHER" | xxd -r -p | base64 -w0
```

```php title="Decrypting it"
// The same key seed used in export.php; $encrypted is the Base64 text printed above
$crypto = new \ByJG\Crypto\OpenSSLCrypto('aes-256-cbc', $keys);
echo $crypto->decrypt($encrypted); // this is a test
```

## JavaScript CryptoJS

The same steps in the browser, with [CryptoJS](https://github.com/brix/crypto-js). PHP hands over
the master key, the IV and the header:

```php title="PHP: the values JavaScript needs"
<?php
$keys = new \ByJG\Crypto\KeySet([/* your key seed */]);

[$masterKey, $iv, $header] = $keys->getKeyAndIv('aes-256-cbc');

header('Content-Type: application/json');
echo json_encode([
    'masterKey' => base64_encode($masterKey),
    'iv' => base64_encode($iv),
    'header' => base64_encode($header),
]);
```

:::caution
Whoever receives a master key can read and forge every message encrypted with it, and the same
master key is used again by other messages. Hand it only to a client you trust, over a secure
connection. The key seed itself must never leave the server.
:::

```html title="JavaScript: encrypting in the library's format"
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>
<script>
  // "params" is the JSON returned by PHP
  var plainText = "myPassword";

  var masterKey = CryptoJS.enc.Base64.parse(params.masterKey);
  var iv = CryptoJS.enc.Base64.parse(params.iv);
  var header = CryptoJS.enc.Base64.parse(params.header);

  // Same derivation as PHP: SHA-256 over the raw bytes of the master key followed by a label
  var encryptionKey = CryptoJS.SHA256(masterKey.clone().concat(CryptoJS.enc.Utf8.parse('encryption')));
  var authKey = CryptoJS.SHA256(masterKey.clone().concat(CryptoJS.enc.Utf8.parse('authentication')));

  var encrypted = CryptoJS.AES.encrypt(plainText, encryptionKey, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });

  // payload = header + ciphertext; result = base64(HMAC + payload)
  var payload = header.clone().concat(encrypted.ciphertext);
  var hmac = CryptoJS.HmacSHA256(payload, authKey);
  var base64Encrypted = CryptoJS.enc.Base64.stringify(hmac.concat(payload));

  console.log(base64Encrypted);
</script>
```

The SHA-256 output is 32 bytes, exactly the key `aes-256-cbc` takes. For a cipher with a shorter
key, keep only the first bytes of `encryptionKey`.

```php title="PHP: decrypting what JavaScript encrypted"
// The same key seed; $encryptedBase64 is the base64Encrypted value from JavaScript
$crypto = new \ByJG\Crypto\OpenSSLCrypto('aes-256-cbc', $keys);
echo $crypto->decrypt($encryptedBase64); // myPassword
```

A complete page that does this against a PHP server is in
[examples/js](https://github.com/byjg/php-crypto/tree/master/examples/js). There the server
derives the two keys and sends them instead of the master key.
