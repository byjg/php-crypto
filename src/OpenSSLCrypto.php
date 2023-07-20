<?php

namespace ByJG\Crypto;

class OpenSSLCrypto extends BaseCrypto
{
    public function __construct($cryptoMethod, $cryptoOptions, $keys)
    {
        $this->cryptoMethod = $cryptoMethod;
        $this->cryptoOptions = $cryptoOptions;
        $this->keys = $keys;
    }

    protected $cryptoMethod = null;
    protected $cryptoOptions = null;

    public function getBlockSize()
    {
        return openssl_cipher_iv_length($this->cryptoMethod);
    }

    public function encrypt($plainText)
    {
        list($key, $iv, $header, $padded) = $this->getKeyAndIv($plainText);
        $encText = openssl_encrypt($padded, $this->cryptoMethod, $key, $this->cryptoOptions, $iv);

        return base64_encode($header . $encText);
    }

    public function decrypt($encryptText)
    {
        list($key, $iv, $cipherText) = $this->decryptHeader($encryptText);

        $res = openssl_decrypt($cipherText, $this->cryptoMethod, $key, $this->cryptoOptions, $iv);
        return $this->pkcs5Unpad($res);
    }

}