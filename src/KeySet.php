<?php

namespace ByJG\Crypto;

class KeySet
{
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
            if (strlen($key) != 64) {
                throw new \InvalidArgumentException("The key must have 32 bytes (encoded as hex -> 64 chars))");
            }

            hex2bin($key);
        }

        $this->keys = $keySet;
    }

    public function getKeyLength(string|null $algorithm): int
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
        $windowSize = 8; // 8-byte scrolling window

        // Calculate max offset to ensure window fits within 32-byte key seed entry
        // For key: need 8 bytes, so max offset is 32 - 8 = 24
        $maxKeyOffset = 32 - $windowSize;

        // For IV: need blockSize bytes, calculate max offset
        $maxIvOffset = 32 - max($blockSize, $windowSize);

        // Generate random parameters
        $bitA = random_int(0, $maxPossibleKeys);  // Key seed entry index for key
        $offsetA = random_int(0, max(0, $maxKeyOffset)); // Offset for key extraction
        $bitB = random_int(0, $maxPossibleKeys);  // Key seed entry index for IV
        $offsetB = random_int(0, max(0, $maxIvOffset)); // Offset for IV extraction

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
     */
    public function restoreKeyAndIv(string $algorithm, string $header): array
    {
        $blockSize = openssl_cipher_iv_length($algorithm);
        $windowSize = 8; // 8-byte scrolling window

        // Parse 4-byte header
        $bitA = ord(substr($header, 0, 1));     // Key seed entry index for key
        $offsetA = ord(substr($header, 1, 1));  // Offset for key extraction
        $bitB = ord(substr($header, 2, 1));     // Key seed entry index for IV
        $offsetB = ord(substr($header, 3, 1));  // Offset for IV extraction

        // Reconstruct key using scrolling window
        $key = $this->getKeyPart($bitA, $offsetA, $windowSize, $algorithm);

        // Reconstruct IV using scrolling window
        $ivMaterial = $this->getKeyPart($bitB, $offsetB, $windowSize, null);
        $iv = substr($ivMaterial, 0, $blockSize);

        return [$key, $iv];
    }

}
