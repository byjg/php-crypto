<?php

namespace ByJG\Crypto;

interface CryptoInterface
{
    public function getKeys();

    public function setKeys($keySet);

    public function getKeyPart($keyNumber, $part);
    
    public function encrypt($plainText);

    public function decryptHeader($encryptText);

    public function decrypt($encryptText);

    public function getBlockSize();
}
