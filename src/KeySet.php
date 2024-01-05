<?php

namespace ByJG\Crypto;

class KeySet
{
    protected $keys = [];

    public function __construct($keySet)
    {
        $this->setKeys($keySet);
    }

    public static function generateKeySet($lines = 32)
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

    protected function setKeys($keySet)
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

    protected function getKeyLength($algorithm)
    {
        if (empty($algorithm)) {
            return 32;
        } else if (Php80::str_contains($algorithm, '-128') || Php80::str_contains($algorithm, 'sm4') || Php80::str_contains($algorithm, 'des-ede')) {
            return 16;
        } else if (Php80::str_contains($algorithm, '-192') || Php80::str_contains($algorithm, 'des-ede3')) {
            return 24;
        } else if (Php80::str_contains($algorithm, '-256')) {
            return 32;
        } else {
            return 24;
        }
    }

    public function getKeyPart($keyNumber, $part, $algorithm)
    {
        $keyPart = $this->getKeys();
        $keyLength = $this->getKeyLength($algorithm);

        if ($part == 1) {
            return substr(hex2bin($keyPart[$keyNumber]), 0, $keyLength);
        } else {
            return substr(hex2bin($keyPart[$keyNumber]), -$keyLength);
        }
    }

    public function getKeyAndIv($algorithm)
    {
        $maxPossibleKeys = count($this->getKeys()) - 1;
        $blockSize = openssl_cipher_iv_length($algorithm);

        $rand = rand(0, floor($blockSize / 2) - 1);
        $bitA = rand(0, $maxPossibleKeys);
        $bitB = rand(0, $maxPossibleKeys);
        $partA = rand(0, 1);
        $partB = rand(0, 1);

        $key = $this->getKeyPart($bitA, $partA, $algorithm);
        $iv = substr($this->getKeyPart($bitB, $partB, null), $rand, $blockSize);

        $bitHeader = $partA << 7 | $partB << 6 | $rand;
        $header = chr($bitHeader) . chr($bitA) . chr($bitB);

        return [$key, $iv, $header];
    }

    public function restoreKeyAndIv($algorithm, $header)
    {
        $bitHeader = ord(substr($header, 0, 1));
        $partA = ($bitHeader & 128) >> 7;
        $partB = ($bitHeader & 64) >> 6;
        $rand = $bitHeader & 63;

        $bitA = ord(substr($header, 1, 1));
        $bitB = ord(substr($header, 2, 1));

        $blockSize = openssl_cipher_iv_length($algorithm);

        $key = $this->getKeyPart($bitA, $partA, $algorithm);
        $iv = substr($this->getKeyPart($bitB, $partB, null), $rand, $blockSize);

        return [$key, $iv];
    }

}