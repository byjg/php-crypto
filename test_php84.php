<?php

require "vendor/autoload.php";

use ByJG\Crypto\KeySet;
use ByJG\Crypto\OpenSSLCrypto;

// Generate a new key set
$keySet = KeySet::generateKeySet(32);
$keys = new KeySet($keySet);

// Create a new OpenSSLCrypto instance
$crypto = new OpenSSLCrypto('aes-256-cbc', $keys);

// Test encryption and decryption
$plainText = "This is a test message for PHP 8.4 compatibility";
$encrypted = $crypto->encrypt($plainText);
$decrypted = $crypto->decrypt($encrypted);

echo "Original: $plainText\n";
echo "Encrypted: $encrypted\n";
echo "Decrypted: $decrypted\n";

// Verify the decrypted text matches the original
if ($plainText === $decrypted) {
    echo "Test passed: Encryption and decryption work correctly.\n";
} else {
    echo "Test failed: Decrypted text does not match original.\n";
}