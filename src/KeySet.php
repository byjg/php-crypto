<?php

namespace ByJG\Crypto;

class KeySet
{
    /** The key and the IV are both derived from 8 bytes taken from a 32-byte key seed entry */
    private const int ENTRY_SIZE = 32;
    private const int WINDOW_SIZE = 8;

    protected array $keys = [];

    public function __construct(array $keySet)
    {
        $this->setKeys($keySet);
    }

    /**
     * @return string[]
     */
    public static function generateKeySet(int $lines = 32): array
    {
        $keySet = [];
        for($i=0; $i<$lines; $i++) {
            $keySet[] = bin2hex(random_bytes(32));
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
            if (!is_string($key) || strlen($key) != 64 || !ctype_xdigit($key)) {
                throw new \InvalidArgumentException("The key must have 32 bytes (encoded as hex -> 64 chars))");
            }
        }

        $this->keys = array_values($keySet);
    }

    public function getKeyLength(string|null $algorithm): int
    {
        if (empty($algorithm)) {
            return 32;
        }

        if (!in_array(strtolower($algorithm), openssl_get_cipher_methods(true))) {
            throw new \InvalidArgumentException("Unknown cipher algorithm '$algorithm'");
        }

        return (int)openssl_cipher_key_length($algorithm);
    }

    /**
     * The highest offset the 8-byte window can start at, for the key and for the IV.
     *
     * @return array{int, int}
     */
    private function getMaxOffsets(string $algorithm): array
    {
        $blockSize = (int)openssl_cipher_iv_length($algorithm);

        return [
            self::ENTRY_SIZE - self::WINDOW_SIZE,
            self::ENTRY_SIZE - max($blockSize, self::WINDOW_SIZE),
        ];
    }

    public function getKeyPart(int $keyNumber, int $offset, int $windowSize, string|null $algorithm): string
    {
        $keyPart = $this->getKeys();
        $keyLength = $this->getKeyLength($algorithm);

        // Extract windowSize bytes starting at offset from the key seed entry
        $rawKey = hex2bin($keyPart[$keyNumber]);
        $window = substr($rawKey, $offset, $windowSize);

        // If the window provides exactly the needed key length, return it
        if ($windowSize >= $keyLength) {
            return substr($window, 0, $keyLength);
        }

        // Otherwise, derive the required key length using key stretching
        // Repeat the window material to fill the required length
        $derivedKey = '';
        while (strlen($derivedKey) < $keyLength) {
            $derivedKey .= hash('sha256', $window . $derivedKey, true);
        }

        return substr($derivedKey, 0, $keyLength);
    }

    /**
     * @param string $algorithm
     * @return array
     */
    public function getKeyAndIv(string $algorithm): array
    {
        $maxPossibleKeys = count($this->getKeys()) - 1;
        $blockSize = openssl_cipher_iv_length($algorithm);
        $windowSize = self::WINDOW_SIZE;
        [$maxKeyOffset, $maxIvOffset] = $this->getMaxOffsets($algorithm);

        // Generate random parameters
        $bitA = random_int(0, $maxPossibleKeys);  // Key seed entry index for key
        $offsetA = random_int(0, $maxKeyOffset);  // Offset for key extraction
        $bitB = random_int(0, $maxPossibleKeys);  // Key seed entry index for IV
        $offsetB = random_int(0, $maxIvOffset);   // Offset for IV extraction

        // Extract key using scrolling window
        $key = $this->getKeyPart($bitA, $offsetA, $windowSize, $algorithm);

        // Extract IV using scrolling window
        $ivMaterial = $this->getKeyPart($bitB, $offsetB, $windowSize, null);
        $iv = substr($ivMaterial, 0, $blockSize);

        // Create 4-byte header
        $header = chr($bitA) . chr($offsetA) . chr($bitB) . chr($offsetB);

        return [$key, $iv, $header];
    }

    /**
     * @param string $algorithm
     * @param string $header
     * @return array
     * @throws \InvalidArgumentException When the header is not one getKeyAndIv() could have produced
     */
    public function restoreKeyAndIv(string $algorithm, string $header): array
    {
        if (strlen($header) != 4) {
            throw new \InvalidArgumentException("The header must have 4 bytes");
        }

        $blockSize = openssl_cipher_iv_length($algorithm);
        $windowSize = self::WINDOW_SIZE;

        // Parse 4-byte header
        $bitA = ord($header[0]);     // Key seed entry index for key
        $offsetA = ord($header[1]);  // Offset for key extraction
        $bitB = ord($header[2]);     // Key seed entry index for IV
        $offsetB = ord($header[3]);  // Offset for IV extraction

        $maxPossibleKeys = count($this->getKeys()) - 1;
        [$maxKeyOffset, $maxIvOffset] = $this->getMaxOffsets($algorithm);
        if ($bitA > $maxPossibleKeys || $bitB > $maxPossibleKeys || $offsetA > $maxKeyOffset || $offsetB > $maxIvOffset) {
            throw new \InvalidArgumentException("The header does not match this key set");
        }

        // Reconstruct key using scrolling window
        $key = $this->getKeyPart($bitA, $offsetA, $windowSize, $algorithm);

        // Reconstruct IV using scrolling window
        $ivMaterial = $this->getKeyPart($bitB, $offsetB, $windowSize, null);
        $iv = substr($ivMaterial, 0, $blockSize);

        return [$key, $iv];
    }

}
