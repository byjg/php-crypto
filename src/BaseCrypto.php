<?php

namespace ByJG\Crypto;


abstract class BaseCrypto implements CryptoInterface
{
    protected $keys = [];

    protected $cryptoMethod = null;
    protected $cryptoOptions = null;



    public static function getKeySet($lines = 32)
    {
        $keySet = [];
        for($i=0; $i<$lines; $i++) {
            $keySet[] = bin2hex(openssl_random_pseudo_bytes(32));
        }

        return $keySet;
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

    public function getKeys()
    {
        return $this->keys;
    }

    public function setKeys($keySet)
    {
        if (count($keySet) < 2 || count($keySet) > 255) {
            throw new \InvalidArgumentException("The key set must have between 2 and 255 keys");
        }

        foreach ($keySet as $key) {
            if (strlen($key) != 64) {
                throw new \InvalidArgumentException("The key must have 32 bytes (encoded as hex -> 64 chars))");
            }

            hex2bin($key);
        }

        $this->keys = $keySet;
    }

    public function getKeyPart($keyNumber, $part)
    {
        $keyPart = $this->getKeys();
        $blockSize = 24;

        if ($part == 1) {
            return substr(hex2bin($keyPart[$keyNumber]), 0, $blockSize);
        } else {
            return substr(hex2bin($keyPart[$keyNumber]), -$blockSize);
        }
    }

    protected function getKeyAndIv($plainText)
    {
        $maxPossibleKeys = count($this->getKeys()) - 1;
        $blockSize = $this->getBlockSize();

        $rand = rand(0, floor($blockSize / 2) - 1);
        $bitA = rand(0, $maxPossibleKeys);
        $bitB = rand(0, $maxPossibleKeys);
        $partA = rand(0, 1);
        $partB = rand(0, 1);

        $key = $this->getKeyPart($bitA, $partA);
        $iv = substr($this->getKeyPart($bitB, $partB), $rand, $blockSize);

        $bitHeader = $partA << 7 | $partB << 6 | $rand;
        $header = chr($bitHeader) . chr($bitA) . chr($bitB);

        return [$key, $iv, $header, $plainText];
    }


    public function decryptHeader($encryptText)
    {
        $cipherText = base64_decode($encryptText);

        $bitHeader = ord(substr($cipherText, 0, 1));
        $partA = ($bitHeader & 128) >> 7;
        $partB = ($bitHeader & 64) >> 6;
        $rand = $bitHeader & 63;

        $bitA = ord(substr($cipherText, 1, 1));
        $bitB = ord(substr($cipherText, 2, 1));

        $blockSize = $this->getBlockSize();

        $key = $this->getKeyPart($bitA, $partA);
        $iv = substr($this->getKeyPart($bitB, $partB), $rand, $blockSize);

        return [$key, $iv, substr($cipherText, 0, 3), substr($cipherText, 3)];
    }

    protected function clearOpenSslErrors()
    {
        while (openssl_error_string() !== false) {
            // clear errors
        }
    }

    protected function throwOpenSslException()
    {
        $error = openssl_error_string();
        if ($error !== false) {
            throw new OpenSSLException("OpenSSL Error: " . $error);
        }
    }

}
