<?php

namespace ByJG\Crypto;


abstract class TripleDes implements CryptoInterface
{

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
        $blockSize = mcrypt_get_block_size(MCRYPT_3DES, MCRYPT_MODE_CBC);

        $bitA = rand(0, $maxPossibleKeys);
        $bitB = rand(0, $maxPossibleKeys);

        $part = rand(0,1);
        $key = $this->getKeyPart($bitA, $part);
        $iv = substr($this->getKeyPart($bitB, 1-$part), 0, $blockSize);

        $padded = $this->pkcs5Pad($plainText, $blockSize);

        $encText = mcrypt_encrypt(MCRYPT_3DES, $key, $padded, MCRYPT_MODE_CBC, $iv);

        return base64_encode(bin2hex(chr($part)) . bin2hex(chr($bitA)) . bin2hex(chr($bitB)) . $encText);
    }

    public function decrypt($encryptText) {

        $cipherText = base64_decode($encryptText);

        $part = ord(hex2bin(substr($cipherText, 0, 2)));
        $bitA = ord(hex2bin(substr($cipherText, 2, 2)));
        $bitB = ord(hex2bin(substr($cipherText, 4, 2)));

        $key = $this->getKeyPart($bitA, $part);
        $iv = substr($this->getKeyPart($bitB, 1-$part), 0, mcrypt_get_block_size(MCRYPT_3DES, MCRYPT_MODE_CBC));

        $res = mcrypt_decrypt(MCRYPT_3DES, $key, substr($cipherText, 6), MCRYPT_MODE_CBC, $iv);

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
