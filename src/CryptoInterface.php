<?php

namespace ByJG\Crypto;

interface CryptoInterface
{
    public function getKeys();

    public function getKeyPart($keyNumber, $part);
    
    public function encrypt($sValue);
    
    public function decrypt($sValue);
}