<?php

namespace ByJG\Crypto;

class OpenSSLCrypto
{
    protected $cryptoMethod = null;
    protected $cryptoOptions = null;

    protected KeySet $keys;

    public function __construct($cryptoMethod, $keys)
    {
        $this->setCryptoMethod($cryptoMethod);
        $this->setCryptoOptions(OPENSSL_RAW_DATA);
        $this->keys = $keys;
    }

    public function encrypt($plainText)
    {
        list($key, $iv, $header) = $this->keys->getKeyAndIv($this->getCryptoMethod());

        $this->clearOpenSslErrors();
        $encText = openssl_encrypt($plainText, $this->getCryptoMethod(), $key, $this->getCryptoOptions(), $iv);
        $this->throwOpenSslException();

        return base64_encode($header . $encText);
    }

    protected function clearOpenSslErrors()
    {
        while (openssl_error_string() !== false) {
            // clear errors
        }
    }

    /**
     * @return null
     */
    protected function getCryptoMethod()
    {
        return $this->cryptoMethod;
    }

    /**
     * @param null $cryptoMethod
     */
    protected  function setCryptoMethod($cryptoMethod): void
    {
        $this->cryptoMethod = $cryptoMethod;
    }

    /**
     * @return null
     */
    protected function getCryptoOptions()
    {
        return $this->cryptoOptions;
    }

    /**
     * @param null $cryptoOptions
     */
    protected function setCryptoOptions($cryptoOptions): void
    {
        $this->cryptoOptions = $cryptoOptions;
    }

    protected function throwOpenSslException()
    {
        $error = openssl_error_string();
        if ($error !== false) {
            throw new OpenSSLException("OpenSSL Error: " . $error);
        }
    }

    public function splitEncryptedText($encryptText)
    {
        $encryptText = base64_decode($encryptText);
        $header = substr($encryptText, 0, 3);
        $cipherText = substr($encryptText, 3);

        return [$header, $cipherText];
    }

    public function decrypt($encryptText)
    {
        list($header, $cipherText) = $this->splitEncryptedText($encryptText);
        list($key, $iv) = $this->keys->restoreKeyAndIv($this->getCryptoMethod(), $header);
        return $this->decryptWithKey($cipherText, $key, $iv);
    }

    public function decryptWithKey($cipherText, $key, $iv)
    {
        $this->clearOpenSslErrors();
        $res = openssl_decrypt($cipherText, $this->getCryptoMethod(), $key, $this->getCryptoOptions(), $iv);
        $this->throwOpenSslException();

        return $res;
    }

    public function getBlockSize()
    {
        return openssl_cipher_iv_length($this->getCryptoMethod());
    }

}