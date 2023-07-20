<?php

namespace ByJG\Crypto;


abstract class BaseCrypto implements CryptoInterface
{
    protected $keys = [];

    public static function getKeySet($lines = 32)
    {
        $keySet = [];
        for($i=0; $i<$lines; $i++) {
            $keySet[] = bin2hex(openssl_random_pseudo_bytes(32));
        }

        return $keySet;
    }

    public function getKeys()
    {
        return $this->keys;
    }

    public function setKeys($keySet)
    {
        if (count($keySet) != 32) {
            throw new \InvalidArgumentException("The key set must have 32 keys");
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

        $rand = rand(0, floor($blockSize/2) - 1);
        $bitA = rand(0, $maxPossibleKeys);
        $bitB = rand(0, $maxPossibleKeys);
        $partA = rand(0,1);
        $partB = rand(0,1);

        $key = $this->getKeyPart($bitA, $partA);
        $iv = substr($this->getKeyPart($bitB, $partB), $rand, $blockSize);

        $padded = $this->pkcs5Pad($plainText, $blockSize);

        $bitHeader = $partA << 7 | $partB << 6 | $rand;
        $header = bin2hex(chr($bitHeader)) . bin2hex(chr($bitA)) . bin2hex(chr($bitB));

        return [$key, $iv, $header, $padded];
    }


    public function decryptHeader($encryptText)
    {
        $cipherText = base64_decode($encryptText);

        $bitHeader = ord(hex2bin(substr($cipherText, 0, 2)));
        $rand = $bitHeader & 63;
        $partA = ($bitHeader & 128) >> 7;
        $partB = ($bitHeader & 64) >> 6;

        $bitA = ord(hex2bin(substr($cipherText, 2, 2)));
        $bitB = ord(hex2bin(substr($cipherText, 4, 2)));

        $blockSize = $this->getBlockSize();

        $key = $this->getKeyPart($bitA, $partA);
        $iv = substr($this->getKeyPart($bitB, $partB), $rand, $blockSize);

        $cipherText = substr($cipherText, 6);

        return [$key, $iv, substr($cipherText, 0, 6), $cipherText];
    }

    protected function pkcs5Pad ($text, $blocksize)
    {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    protected function pkcs5Unpad($text)
    {
        $pad = $text[strlen($text)-1];
        return rtrim($text, $pad);
    }

}
