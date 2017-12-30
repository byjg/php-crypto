<?php

namespace ByJG\Crypto;


abstract class AES extends BaseCrypto
{
    public function encrypt($plainText)
    {
        $this->cryptoMethod = "aes-256-cbc";
        $this->cryptoOptions = OPENSSL_RAW_DATA;

        return parent::encrypt($plainText);
    }

    public function decrypt($encryptText) {

        $this->cryptoMethod = "aes-256-cbc";
        $this->cryptoOptions = OPENSSL_RAW_DATA;

        return parent::decrypt($encryptText);
    }
}
