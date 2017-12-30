<?php

require __DIR__ . "/../vendor/autoload.php";
require "SampleTripleDes.php";

use ByJG\Crypto\TripleDes;

// backward compatibility
if (!class_exists('\PHPUnit\Framework\TestCase')) {
    class_alias('\PHPUnit_Framework_TestCase', '\PHPUnit\Framework\TestCase');
}

class TripleDesTest extends \PHPUnit\Framework\TestCase
{

    /**
     * @var TripleDes
     */
    protected $object;

    public function setUp()
    {
        $this->object = new \SampleTripleDes();
    }

    public function tearDown()
    {
        $this->object = null;
    }

    public function testGetKeys()
    {
        $this->assertEquals(
            [
                '85513d3ddbad668d8420200ecb513917bbc729d88aaf2778c4b321deab55eb5c',
                'daefe2720925562239486dcd7bb748cf7027daca3ce2afd53889bb5d00cf5b75',
                'aba2fbc08a0264cea08c6b3eb6141bdbc9d1990368ee1652116822ecb5dad2ec',
                '884f755db0547b7c54f0ad6e58c1a2037b337411bcc0931d1249ab04c404cf9c',
                '2ad3a4acd4d99ba15db0ebac1d6247131754e8d2a53486e891d035c7b91cc02e',
                '9cb0da7b1c677a549d20bead576c883f8a0c51b53a49aa4a265ccdcbcb974aa7',
                '0789c4f9b005a723174c89be5d43e1182a2df84e41c698064191b8a36990dccc',
                '6b3970b2c7db17864de955e21c43f0c46512ebfdc0711da492f2251d03a6c619',
                '51695ef0cfb4ed38189e515c1c31610e515093b90dd3d39647cf46efe12f86e1',
                '77fa9c480085f0e1b01c5dabae82d3836849ef8288cf40b66d10a8d0b9847cd0',
                'c93529bf156723482950c829e89a84d8affb27a3b89c20915e1d1b1ddc3f54d3',
                '2a331cca5c45f132711f6ad455bb090659004c8e31159832f4cf64e6ef812ef5',
                'b76f66c09297141f3a9a8a3db9390d9289a598a11da2e4c01e8c401a32651428',
                'faff1d7aa3749222f73ae97e3a9998f154dbe8a55d524f8f131f9d3d67d0dc51',
                '9da9d3bab2de071818ce4e50e15018bb85b16a950d5f15ade75507b647280aac',
                '0ea499d1e8bc7462a59eea42eb9b15a2e0d1d50218e0ea75f0d57c4154250876',
                '575e47d3066fc1481678a62f5272bc527544c17111cf4ba2f5949a9cd9ee2bd5',
                'ddd308019be439ac79736084587f738cfd1cfe6df82b688f661c10314a97c968',
                'a5aee011e9f250f53682ac8598cb23d73466a815b76d63fcf61e2d7a7a6b8c68',
                '0bb7ed71c04a6583998cc3bb914d0d95f0ce372ab0a347bcc1b62d146c10cdee',
                'e1c1f497a9c622be28a8328fb02a2bfeb4413fdfb5f786fb864bd68dc3e4e87a',
                'cf2ce1bc99a889a9c62847fb4751bf4affa126e911ea155523e079d1f875007c',
                '4e9699c3b74e27b4fb4994e6506084dbac5ef8dee297a79bb84105844a50624a',
                '1a85ab3a4417dec226a031dfa3c00f460af5ee76db58a7b3eb96711cc8e77a9b',
                '936ccafe3f1fc73551c5b9a26c2dc9f79cad26ed0a633613db127b4ba6930274',
                '377cc8b3589730c8085bd4a26dc78bd93484d871e8a5f5182a834a2667ab87c2',
                '733f0774032d6abe4cdb7785d66ef45ac197822ab76547e92949f3ce4d687d6e',
                '8981f485857f7d6609319734ec5ac9715db673c34b06179508c66cfcc421b305',
                'd1923f2f8e7dda3145dc031a4d5ba38f191d2932e105a5294d0dfc0c4edfa4ad',
                '175efea243ded4bdd449402299e93a564948963cfdebb8ce21c2d0f39e2c0ea7',
                'a58b1e364287ac22bad993124e480d591fdc7502925781b7fe15f718a11e799e',
                '2ce8d9289b1eb73e22e8ba6686b7c919558e43718939db34b9729b1efb89e2a8',
            ],
            $this->object->getKeys()
        );
    }

    public function testGetKeyPart()
    {
        $this->assertEquals(hex2bin('85513d3ddbad668d8420200ecb513917bbc729d88aaf2778'), $this->object->getKeyPart(0,1));
        $this->assertEquals(hex2bin('8420200ecb513917bbc729d88aaf2778c4b321deab55eb5c'), $this->object->getKeyPart(0,2));
        $this->assertEquals(hex2bin('2ce8d9289b1eb73e22e8ba6686b7c919558e43718939db34'), $this->object->getKeyPart(31,1));
        $this->assertEquals(hex2bin('22e8ba6686b7c919558e43718939db34b9729b1efb89e2a8'), $this->object->getKeyPart(31,0));
    }

    public function testEncrypt()
    {
        // Create a for to ensure the RAND value will not cause an error
        for ($i=0; $i<20; $i++) {
            $encrypted = $this->object->encrypt('somevalue');
            $this->assertNotEmpty($encrypted);
            $this->assertNotEquals($encrypted, 'somevalue');
            $decrypted = $this->object->decrypt($encrypted);
            $this->assertEquals('somevalue', $decrypted);
        }
    }
}
