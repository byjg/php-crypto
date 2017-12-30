<?php

namespace ByJG\Crypto;


abstract class BaseCrypto implements CryptoInterface
{

    protected $cryptoMethod = null;
    protected $cryptoOptions = null;

    abstract public function getKeys();

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

    public function encrypt($plainText)
    {
        $maxPossibleKeys = count($this->getKeys()) - 1;

        $bitA = rand(0, $maxPossibleKeys);
        $bitB = rand(0, $maxPossibleKeys);

        $blockSize = openssl_cipher_iv_length($this->cryptoMethod);

        $part = rand(0,1);
        $key = $this->getKeyPart($bitA, $part);
        $iv = substr($this->getKeyPart($bitB, 1-$part), 0, $blockSize);

        $padded = $this->pkcs5Pad($plainText, $blockSize);

        $encText = openssl_encrypt($padded, $this->cryptoMethod, $key, $this->cryptoOptions, $iv);

        return base64_encode(bin2hex(chr($part)) . bin2hex(chr($bitA)) . bin2hex(chr($bitB)) . $encText);
    }

    public function decrypt($encryptText) {

        $cipherText = base64_decode($encryptText);

        $part = ord(hex2bin(substr($cipherText, 0, 2)));
        $bitA = ord(hex2bin(substr($cipherText, 2, 2)));
        $bitB = ord(hex2bin(substr($cipherText, 4, 2)));

        $blockSize = openssl_cipher_iv_length($this->cryptoMethod);
        $key = $this->getKeyPart($bitA, $part);
        $iv = substr($this->getKeyPart($bitB, 1-$part), 0, $blockSize);

        $res = openssl_decrypt(substr($cipherText, 6), $this->cryptoMethod, $key, $this->cryptoOptions, $iv);

        return $this->pkcs5Unpad($res);
    }


    protected function pkcs5Pad ($text, $blocksize)
    {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    protected function pkcs5Unpad($text)
    {
        $pad = ord($text{strlen($text)-1});
        if ($pad > strlen($text)) {
            return false;
        }
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) {
            return false;
        }
        return substr($text, 0, -1 * $pad);
    }

}
