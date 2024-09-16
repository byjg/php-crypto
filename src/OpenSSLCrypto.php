<?php

namespace ByJG\Crypto;

class OpenSSLCrypto
{
    protected string $cryptoMethod;
    protected int $cryptoOptions;

    protected KeySet $keys;

    public function __construct(string $cryptoMethod, KeySet $keys)
    {
        $this->setCryptoMethod($cryptoMethod);
        $this->setCryptoOptions(OPENSSL_RAW_DATA);
        $this->keys = $keys;
    }

    /**
     * @param string $plainText
     * @return string
     * @throws OpenSSLException
     */
    public function encrypt(string $plainText): string
    {
        list($key, $iv, $header) = $this->keys->getKeyAndIv($this->getCryptoMethod());

        $this->clearOpenSslErrors();
        $encText = openssl_encrypt($plainText, $this->getCryptoMethod(), $key, $this->getCryptoOptions(), $iv);
        $this->throwOpenSslException();

        return base64_encode($header . $encText);
    }

    protected function clearOpenSslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // clear errors
        }
    }

    /**
     * @return string|null
     */
    protected function getCryptoMethod(): ?string
    {
        return $this->cryptoMethod;
    }

    /**
     * @param string $cryptoMethod
     */
    protected  function setCryptoMethod(string $cryptoMethod): void
    {
        $this->cryptoMethod = $cryptoMethod;
    }

    /**
     * @return int|null
     */
    protected function getCryptoOptions(): ?int
    {
        return $this->cryptoOptions;
    }

    /**
     * @param int $cryptoOptions
     */
    protected function setCryptoOptions(int $cryptoOptions): void
    {
        $this->cryptoOptions = $cryptoOptions;
    }

    /**
     * @return void
     * @throws OpenSSLException
     */
    protected function throwOpenSslException(): void
    {
        $error = openssl_error_string();
        if ($error !== false) {
            throw new OpenSSLException("OpenSSL Error: " . $error);
        }
    }

    /**
     * @param string $encryptText
     * @return array
     */
    public function splitEncryptedText(string $encryptText): array
    {
        $encryptText = base64_decode($encryptText);
        $header = substr($encryptText, 0, 3);
        $cipherText = substr($encryptText, 3);

        return [$header, $cipherText];
    }

    public function decrypt(string $encryptText): bool|string
    {
        list($header, $cipherText) = $this->splitEncryptedText($encryptText);
        list($key, $iv) = $this->keys->restoreKeyAndIv($this->getCryptoMethod(), $header);
        return $this->decryptWithKey($cipherText, $key, $iv);
    }

    /**
     * @param string $cipherText
     * @param string $key
     * @param string $iv
     * @return false|string
     * @throws OpenSSLException
     */
    public function decryptWithKey(string $cipherText, string $key, string $iv): string|false
    {
        $this->clearOpenSslErrors();
        $res = openssl_decrypt($cipherText, $this->getCryptoMethod(), $key, $this->getCryptoOptions(), $iv);
        $this->throwOpenSslException();

        return $res;
    }

    /**
     * @return false|int
     */
    public function getBlockSize(): int|false
    {
        return openssl_cipher_iv_length($this->getCryptoMethod());
    }

}