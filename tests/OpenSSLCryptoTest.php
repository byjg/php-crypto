<?php

require __DIR__ . "/../vendor/autoload.php";

use ByJG\Crypto\BaseCrypto;
use ByJG\Crypto\OpenSSLCrypto;

class OpenSSLCryptoTest extends \PHPUnit\Framework\TestCase
{

    protected $keys = null;

    public function setUp(): void
    {
        if (empty($this->keys)) {
            $this->keys = BaseCrypto::getKeySet();
        }
    }

    public function providerData()
    {
        return [
            [ 'aes-256-cbc', OPENSSL_RAW_DATA ],
            [ 'aes-256-cbc', OPENSSL_ZERO_PADDING ],
            [ 'des-ede3-cbc', OPENSSL_RAW_DATA ],
            [ 'des-ede3-cbc', OPENSSL_ZERO_PADDING ]
        ];
    }


    public function testGetKeyPart()
    {
        $object = new OpenSSLCrypto(
            'aes-256-cbc',
            OPENSSL_RAW_DATA,
            [
                '51f7664d55c6c00640a78be71ceab0e5234e59c5f8007613584f27f28c2af2e6',
                'daaec6ba804b3539e75733470453804031e37cb8d52a9d284c8bcf225c3d455b',
                'cd74a10191652cbb8a7cf64247914b79b133de55cbf207cf7e47d6d3ba6203b6',
                'b63371448c6e94243721cf5e8c32f6d04c3cbeb730d8e4afa25063d1a9943c6c',
                'c229e3ec9baff4cc05b5cbf19f93b9190546a99336e8d132db61a4556a9ec36d',
                'ca1675864a52ba9a32f988e727c869a1d2cd7069ae1be2f60114697ae979a694',
                'dcfe39d7e991c83536a71ff3aec0bc3b2c776aa48e95643e856827285950ab71',
                '08a71a109cb8441d34f68654c455d32e959ea4b143d430a239b4c314c3828852',
                '66e2076e300dc690ec4c3c6bd3cf4ed08d43cff1687164272581519b0e357804',
                '00daba96b70f3e1bea5aa4995b54dc399fa47e631d9a9e7641c787c03655ba03',
                'a52308b73f30886eadf2584ec68d5a918cd5e0588cd1e3b4db982fa8d93fcbf0',
                '2302930e237a137532eb95e8dc6d0ffe731d8c0d443f61601283f5c0c305b516',
                'baf6fefafe04c4c7f42cded5634fe7c027517cc75c30926f51cb7117f8dab64f',
                'c477347de93a9dfcb494dfe782a5adba5bbfc06491793d63c3808cd15941f71d',
                '499ea329042cd332582d46d59e7ee904202e3a06e140a978151dc025dbdd4d5d',
                '04e5b696121bd3529fee15ecc9c834fa3f0ebbdfde1fb189eb7bfaf798fb929a',
                '54ab545234672c0e43010bae1c501d47ca674130dfe34c984eebe4a82394a3d8',
                'd8bd089f3fc699e4c13f56dd358e9805d956409fe9d512799af4a911652209b6',
                'd3fc3bdaf65870d1b5e9baeacda1d3c98d7fbb1087a82327ef98f839be405765',
                '465a035df2cfbb0eae34814254f3f54d06e8425b100f7a3c61d9d5afc9c9a556',
                '31f29bae898e8aff38959f9cc6828d1dd59fe4395fb7588a2bcb8ea9589b8fbb',
                '33a1d0241c1180f030e541ef7438f4af6a6195589485d5a96da311ae0b83fdae',
                'e3db13d35fafc7b6c18088e88267578536583a9f37e817b6e64a57ec9b2ce1ff',
                '7b2993a928dfd2bf4b1c45af7fc0b5dc596889c8097a14f89ad4a7bef34b0a01',
                '853434e5d16075e1a61ed7568479bb6e989b2366e05a1756d999c53ed0730e6b',
                'e97c6597707578e43c63b4a33e100230bc1d27b473938dbd6ba5f32a2629d8d8',
                'bd9f604026dae69daf2dd1f10a24107bf9efb2f19baac49e1853b075e2ce6583',
                'd2ae4106ed0b605521866105a24895db91ae33a2648c87c424fcadf3edeaaf05',
                'e5cdc2e259675cd1c9d4d950196685f5305d03850fd5a6a1c1a99e025be48a0a',
                'ed301c96be3a284e2dbf033f29e5431c9486597e9ce18bc13e6432104448abd4',
                '3e090b7e7b65a372df1a04d70359c8bb7ac8cade0ccc468b3e60352da2b2bd1e',
                '2a81c637c95fc77fc441c155a9ebdc2d180c6085fcd0231ec14ed45e30e85e6e',
            ],
        );

        $this->assertEquals(hex2bin('51f7664d55c6c00640a78be71ceab0e5234e59c5f8007613'), $object->getKeyPart(0,1));
        $this->assertEquals(hex2bin('40a78be71ceab0e5234e59c5f8007613584f27f28c2af2e6'), $object->getKeyPart(0,0));
        $this->assertEquals(hex2bin('2a81c637c95fc77fc441c155a9ebdc2d180c6085fcd0231e'), $object->getKeyPart(31,1));
        $this->assertEquals(hex2bin('c441c155a9ebdc2d180c6085fcd0231ec14ed45e30e85e6e'), $object->getKeyPart(31,0));
    }

    /**
     * @dataProvider providerData
     */
    public function testEncrypt($method, $options)
    {
        $object = new OpenSSLCrypto($method, $options, $this->keys);
        // Create a for to ensure the RAND value will not cause an error
        for ($i=0; $i<20; $i++) {
            $encrypted = $object->encrypt('somevalue');
            $this->assertNotEmpty($encrypted);
            $this->assertNotEquals('somevalue', $encrypted);
            $decrypted = $object->decrypt($encrypted);
            $this->assertEquals('somevalue', $decrypted);
        }
    }
}
