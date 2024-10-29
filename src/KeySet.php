<?php

namespace ByJG\Crypto;

class KeySet
{
    protected array $keys = [];

    public function __construct($keySet)
    {
        $this->setKeys($keySet);
    }

    /**
     * @return string[]
     */
    public static function generateKeySet($lines = 32): array
    {
        $keySet = [];
        for($i=0; $i<$lines; $i++) {
            $keySet[] = bin2hex(openssl_random_pseudo_bytes(32));
        }

        return $keySet;
    }

    public function getKeys(): array
    {
        return $this->keys;
    }

    /**
     * @param array $keySet
     * @return void
     */
    protected function setKeys(array $keySet): void
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

    protected function getKeyLength(string|null $algorithm): int
    {
        if (empty($algorithm)) {
            return 32;
        } else if (str_contains($algorithm, '-128') || str_contains($algorithm, 'sm4') || str_contains($algorithm, 'des-ede')) {
            return 16;
        } else if (str_contains($algorithm, '-192') || str_contains($algorithm, 'des-ede3')) {
            return 24;
        } else if (str_contains($algorithm, '-256')) {
            return 32;
        } else {
            return 24;
        }
    }

    public function getKeyPart(int $keyNumber, int $part, string|null $algorithm): string
    {
        $keyPart = $this->getKeys();
        $keyLength = $this->getKeyLength($algorithm);

        if ($part == 1) {
            return substr(hex2bin($keyPart[$keyNumber]), 0, $keyLength);
        } else {
            return substr(hex2bin($keyPart[$keyNumber]), -$keyLength);
        }
    }

    /**
     * @param string $algorithm
     * @return array
     */
    public function getKeyAndIv(string $algorithm): array
    {
        $maxPossibleKeys = count($this->getKeys()) - 1;
        $blockSize = openssl_cipher_iv_length($algorithm);

        $rand = rand(0, intval(floor($blockSize / 2)) - 1);
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

    /**
     * @param string $algorithm
     * @param string $header
     * @return array
     */
    public function restoreKeyAndIv(string $algorithm, string $header): array
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