<?php

namespace ByJG\Crypto;

interface CryptoInterface
{
    public function getKeys();

    public function setKeys($keySet);

    public function getKeyPart($keyNumber, $part);
    
    public function encrypt($sValue);

    public function decryptHeader($cipherText);

    public function decrypt($sValue);

    public function getBlockSize();
}
