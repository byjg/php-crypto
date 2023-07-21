# Advanced uses of KeySet class

## Get the key and iv dynamically

The KeySet class can provide the dynamic key for your encryption. 

```php
<?php
$keys = new \ByJG\Crypto\KeySet([
    // ...
])

list($key, $iv, $header) = $keys->getKeyAndIv($algorithm);
echo base64_encode($key) . "\n";
echo base64_encode($iv) . "\n";
echo base64_encode($header) . "\n";
```

The `getKeyAndIv()` method will return a list with the key, the iv and the header. 
The key and iv is based on the Key and Iv Length of the algorithm.

The header can be used to restore the key and iv later. 

## Restore the key and iv

With the header you can restore the key and iv later.

```php
<?php
$keys = new \ByJG\Crypto\KeySet([
    // ...
])

list($key, $iv) = $keys->restoreKeyAndIv($algorithm, $header);
echo base64_encode($key) . "\n";
echo base64_encode($iv) . "\n";
```

## Decrypt using the key and iv

```php
<?php
$object = new OpenSSLCrypto($algorithm, $keys);
echo $crypto->decryptWithKey($cypher, $key, $iv) . "\n";
``` 
