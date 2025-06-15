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
     * Derives encryption and authentication keys from a master key
     * Respects the algorithm's required key length
     */
    private function deriveKeys(string $masterKey, string $algorithm): array
    {
        // Get the required key length for this algorithm
        $keyLength = $this->keys->getKeyLength($algorithm);

        // Derive encryption key with proper length
        $encryptionKey = substr(hash('sha256', $masterKey . 'encryption', true), 0, $keyLength);

        // Always use 32 bytes for HMAC key regardless of encryption algorithm
        $authKey = hash('sha256', $masterKey . 'authentication', true);

        return [$encryptionKey, $authKey];
    }

    /**
     * Constant-time string comparison to prevent timing attacks
     */
    private function hashEquals(string $known, string $user): bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($known, $user);
        }

        // Fallback implementation for older PHP versions
        if (strlen($known) !== strlen($user)) {
            return false;
        }

        $result = 0;
        for ($i = 0; $i < strlen($known); $i++) {
            $result |= ord($known[$i]) ^ ord($user[$i]);
        }

        return $result === 0;
    }

    /**
     * @param string $plainText
     * @return string
     * @throws OpenSSLException
     */
    public function encrypt(string $plainText): string
    {
        list($masterKey, $iv, $header) = $this->keys->getKeyAndIv($this->getCryptoMethod());
        list($encryptionKey, $authKey) = $this->deriveKeys($masterKey, $this->getCryptoMethod());

        $this->clearOpenSslErrors();
        $encText = openssl_encrypt($plainText, $this->getCryptoMethod(), $encryptionKey, $this->getCryptoOptions(), $iv);
        $this->throwOpenSslException();

        // Create the payload: header + ciphertext (IV is embedded in header)
        $payload = $header . $encText;

        // Calculate HMAC over the entire payload for authentication
        $hmac = hash_hmac('sha256', $payload, $authKey, true);

        // Return: base64(HMAC + payload)
        return base64_encode($hmac . $payload);
    }

    protected function clearOpenSslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // clear errors
        }
    }

    /**
     * @return string
     */
    protected function getCryptoMethod(): string
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
     * @return int
     */
    protected function getCryptoOptions(): int
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
     * @throws OpenSSLException
     */
    public function splitEncryptedText(string $encryptText): array
    {
        $encryptText = base64_decode($encryptText);

        if ($encryptText === false) {
            throw new OpenSSLException("Invalid base64 encoding");
        }

        // Format: HMAC(32) + header(3) + ciphertext
        if (strlen($encryptText) < 32 + 3) {
            throw new OpenSSLException("Encrypted text too short");
        }

        $hmac = substr($encryptText, 0, 32);
        $payload = substr($encryptText, 32);
        $header = substr($payload, 0, 3);
        $cipherText = substr($payload, 3);

        return [$hmac, $payload, $header, $cipherText];
    }

    public function decrypt(string $encryptText): bool|string
    {
        try {
            list($receivedHmac, $payload, $header, $cipherText) = $this->splitEncryptedText($encryptText);

            // Restore keys from header using the original KeySet logic
            list($masterKey, $iv) = $this->keys->restoreKeyAndIv($this->getCryptoMethod(), $header);
            list($encryptionKey, $authKey) = $this->deriveKeys($masterKey, $this->getCryptoMethod());

            // Calculate expected HMAC
            $expectedHmac = hash_hmac('sha256', $payload, $authKey, true);

            // Constant-time HMAC verification to prevent timing attacks
            if (!$this->hashEquals($expectedHmac, $receivedHmac)) {
                throw new OpenSSLException("Authentication failed - data has been tampered with");
            }

            // Only decrypt if authentication passes
            return $this->decryptWithKey($cipherText, $encryptionKey, $iv);

        } catch (OpenSSLException $e) {
            // Re-throw OpenSSL exceptions
            throw $e;
        } catch (\Exception $e) {
            // Convert any other exception to OpenSSL exception to avoid information leakage
            throw new OpenSSLException("Decryption failed");
        }
    }

    /**
     * @param string $cipherText
     * @param string $key
     * @param string $iv
     * @return string|false
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
     * @return int|false
     */
    public function getBlockSize(): int|false
    {
        return openssl_cipher_iv_length($this->getCryptoMethod());
    }

}
