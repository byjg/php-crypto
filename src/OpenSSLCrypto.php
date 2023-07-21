<?php

namespace ByJG\Crypto;

class OpenSSLCrypto extends BaseCrypto
{
    public function __construct($cryptoMethod, $keys)
    {
        $this->setCryptoMethod($cryptoMethod);
        $this->setCryptoOptions(OPENSSL_RAW_DATA);
        $this->setKeys($keys);
    }

    public function getBlockSize()
    {
        return openssl_cipher_iv_length($this->getCryptoMethod());
    }

    public function encrypt($plainText)
    {
        list($key, $iv, $header, $plainText) = $this->getKeyAndIv($plainText);

        $this->clearOpenSslErrors();
        $encText = openssl_encrypt($plainText, $this->getCryptoMethod(), $key, $this->getCryptoOptions(), $iv);
        $this->throwOpenSslException();

        return base64_encode($header . $encText);
    }

    public function decrypt($encryptText)
    {
        list($key, $iv, $header, $cipherText) = $this->decryptHeader($encryptText);

        $this->clearOpenSslErrors();
        $res = openssl_decrypt($cipherText, $this->getCryptoMethod(), $key, $this->getCryptoOptions(), $iv);
        $this->throwOpenSslException();

        return $res;
    }

}