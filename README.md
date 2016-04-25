# Crypto

## Description

 A generic repository for implement cryptographic algorithms with a customizable strong key generator.
 The algorithm is well-know, but the major problem is HOW to store the symmetric key.

 With this library you do not need store the key. It is generate dynamically for each encrypting.

## How It Works?

 The algorithm must be inherited with the proper keys.

 Follow the steps:

  1. Install the component

  ```
  composer require "byjg/crypto=1.0.*"
  ```

  2. Create your own class with your own key seed.

  ```
  php vendor/bin/create-keys.php > myclass.php
  ```

  3. Call your class from your program

  ```php
  $myclass = new MyClass();

  // Encrypt the text
  $encrypted = $myclass->encrypt('My text needs to be cryptographed');

  // Decifer the text
  echo $myclass->decrypt($encrypted);
  ```

**Important Note**

Besides the keys are random, you cannot change it after encrypt the code.
If you do this the encrypted code cannot be restored to the original text.


## Example

Below a full example:

```php
require "vendor/autoload.php";

class MyClass extends \ByJG\Crypto\Rijndael
{
    public function getKeys()
    {
        return [
            '14dca647bcc087f67b1528cea11094838f5bd2276a08dcabc491c1823afc51dd',
            '9cc0fd22a3dc2fb3d444e0721e5d02f5c39f9d6b7c41c010a28e06e861f54c8b',
            'e7b965f8b401c06d5180f50f49eb9797ad24fef62b20bcde03456d4ea4006e83',
            'd06b7ff23bd76b19bc1283f28a00bb91cccdf6bd163354f099710898e31ac487',
            'b4bed7d50032556780b303f8cfea612b637ab8935443af4219dd9eb06d4d7b01',
            '0b2f4cb0107ab6946938f2c836cdca74f7e2b1c7482dd2942720ccc755b20097',
            'dcd24b8aa48d2bcd2d0b19764088e7d4343cfee6a15c9f805b58e45b6224c2f5',
            '628b889c7471e149724973ee96a1c5728c61f11c45e3ae6314a321c7b3488bde',
            '4e10b6af85f83951f23514d3c9d1248d1a1777ff114a6768ae116c2a72bc4bc3',
            'da13fce62e22f5919efe8f0cb498f067797e5fc68a94c45c9ae9d1717f82555d',
            '5bd0600dbca418c8166ffc0617e24f472f147424c58dfd4859cde2cd6a98dee7',
            '533c32c8e010920471e2462ba88f9c63278f9cdd7f12adde4a6e15595a56783d',
            '13beb307499b0d911c6ea4c12b9e1131c51693b8918ac5a76c09e86477b28b5a',
            'e966e4d659c99a58da41c305de0e479b4885f83ddb30476955ad28fd9b9e2d7a',
            'b7a6b7535547dd27963e2bb34630edcf81364ae998fdd68356772b300b65dbbc',
            'f00a1fd6ac5e8bb774c66ef908052f95c9d654df117958fc13a1b5056ddb331b',
            '297e13efdd279687af8c70158b446a4724c4a17989eb0fc93ee87606e958fc9c',
            '27a7e110e61076e4901822c940c294f29abbc659370480cd234473c0c90e10ef',
            'd28e4c29007269902711ae177e4c882a4893f1fa47a987872879b0a785cf8c20',
            'f3be6dc7b34df6aafdc3bd5705fd37d73291ac5a15fe7fd4d39497b43e87dd28',
            '8782a68a904d269ae01bb1705dd1b59047749dd07b5b486e5b79b04660054c1e',
            '21c05ba1cf9028f35ab3fd02e46dab733f8957e6b003e5ba8ea9917fa1ad2809',
            '722a9fe048b6aef9407c5ef7cb76896422ef0add38e5db4afd649a7c7ea1f905',
            '6b233fb3e56e55236ab6c862cb982c4df5dde4ca44361b02cd5915160966d3c5',
            'bd6802bc1252316c44e277bbdfdac8712223a445899d77f9d996286f2c499668',
            'e58088cdef444792501a21813ff520c3fd05cf249b958e0b92fd50142eff74d5',
            '9ca20ff424531314ccfd0e067ced0fbc078df65c77d9c5d30470058e6e2fc83c',
            'd50f461eab2cb5855d44bb753710193970c646b6017ce2522081d337188ee28d',
            '9473c14be30ae90db3d16014a538ce6b19d2477bbf1294793540c19559ed1363',
            '20ad5fed300d150305ad48eb1f9b72cc5d24645d3e736ad5c66e6aeee6dcea88',
            '522b058ea3c9cb29c010c431b30e6b6449994e03dc6434965c941e8c465881eb',
            'dec0adad3df3e8c9f5eb135902970c59cd75fc7c1b52ba41ce8ec5b1351e74dc',
        ];
    }
}

$x = new MyClass();
$enc = $x->encrypt('My secret text needs to be encrypted');
echo $enc . "\n";

echo $x->decrypt($enc) . "\n";
```
