// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";

contract KeyGen31Groth16Verifier is Test {
    Groth16Verifier public verifier;

    function setUp() public {
        verifier = new Groth16Verifier();
    }

    function testVerifyAlice() public view {
        bool result = verifier.verifyProof(
            [
                0x0730d45e94d07a4b54f225fd0d0b89bae66f89d8731f9cc50f6a87e072871ea6,
                0x2f20d1bdef6a6417b268bd954cd8e1d4be12d4cd51fa05eb9b76b990f931fe7f
            ],
            [
                [
                    0x19a178b3af5e560e9563744674e8deef661468e0b64848670b395a1b98d93e3c,
                    0x047d859e0c4c151d55a4a983a33e7c15df8ef3a2d3c77a8ac5049238e3305788
                ],
                [
                    0x0ed5a75f3e1d43fa555c9525912f10d7d30a344447ea6724df6df995615e0c64,
                    0x0570c2f37467f1eaf8f351065545942b2624fabcb908a1ea483a4c2c913ef872
                ]
            ],
            [
                0x00176fd3aa2c901a0b49edd8a05fbb7aae532d5e36c355939f9cdc617a63e5d3,
                0x21ea25e4273c82581c7bc0040f61a6b1ddc0de7cc86fda106554880bacf57c47
            ],
            [
                0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                0x03f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3,
                0x1713acbc11e0f0fdaebbcedceed52e57abf30f2b8c435f013ce0756e4377f097,
                0x28145c47c630ed060a7f10ea3d727b9bc0d249796172c2bcb58b836d1e3d4bd4,
                0x06fc7aa21491e4b6878290f06958efa50de23e427d7b4f17b49b8da6191ad41f,
                0x28bb5603f454ca0e93975292a64b5e2627508939c34f75110b1f564b5c573700,
                0x12297ee0bfbd08ff417e17f98ceb6fd1fd0ebf7591dfc240cf863ee809f0fd74,
                0x11465b22b395b507b15fd06b33eb1074f067f9ba6638aca490cdfceef16fc3c0,
                0x1d0c22e0b65e28a2dda5d1f7963f17576bb6e1ac6fda44d1f64688c9f4fd10d3,
                0x2918af65f63e3619ac5cbcc3771e124f8fdaa06b73e45a84472999dbf2115e8e,
                0x25f159ef60c19fa55bdeeac713eab1bc69e41f7e9079f7bffdd0ef7d7381166a,
                0x1a53af8466e5d476a6183f57ccfd6f1ed98729b972a40459c317547a390ad20d,
                0x0e20e6c71ff0732a2cc47e78e55e1dca63dadf085b756a12e8cf384097cbdab2,
                0x20bb39169676c06bd11bc45475ca73499e5e1bd6ef5934908be9b1e7ed261f93,
                0x0000000000000000000000000000000000000000000000000000000000000001,
                0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                0x03f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3,
                0x035ed813d62de4efaec2090398ec8f221801a5d6937e71583455587971f82372,
                0x0a9764b67db417148efa93189bc63edecad9416e5923f985233f439fe53d4368,
                0x03bb75e80a39e8afcee4f396477440968975a58b1a5f2222f48e7895bf4d5537,
                0x2d21805332ed46c9a5b57834e87c0395bc07a7c4ded911184427cc0c1cae8e37,
                0x2e0e33932fed970f0a6502ccdbd31d9f53d869dd97047e8163b61b64ea184893,
                0x046dc1740048f99098f97b9a74f725bc21ae5248eeb9e6385dbdc0b5e128c558,
                0x15819576a5b57223acfbc67cc5af75400ebefa3a418e76d13de46e259e363171
            ]
        );
        assert(result);
    }

    function testVerifyBob() public view {
        bool result = verifier.verifyProof(
            [
                0x1775f93c20a9d661e64c77d5b926242dc180f504878e185b3df0e2ae078c66dc,
                0x26d55220a7396de0477d01d9e72163d74b6b3b1642ed262bbcfce6ec250739ff
            ],
            [
                [
                    0x2dc70a7ecc35079e827c98b9fb27e67c0483fe924b93e8d07932791981c98509,
                    0x2dec711659f448b6f6a483e347ea64c75b075f3fefb3d9a0f0792eb8ae171c1b
                ],
                [
                    0x138101131f156b73f0a872f28b8ebe59e87d876462a64cf9af1f542be021f727,
                    0x16523fe5288ca03c732ea124ed345a31da9124c357e792bcde2f6ae0e2119318
                ]
            ],
            [
                0x194a217452c303c8c4c60ffa9b9077d54d8aeb70b50ddbe52e63f185f8a3b271,
                0x0930f3480ecb9d0e358348e644c93fe60dd31f991d1cdcc241b550b973db6715
            ],
            [
                0x035ed813d62de4efaec2090398ec8f221801a5d6937e71583455587971f82372,
                0x0a9764b67db417148efa93189bc63edecad9416e5923f985233f439fe53d4368,
                0x23c80416edd379bde086351fc0169cfa69adff2c0f0ab04ca9622b099e597489,
                0x130cf58590a10bdf2b75d0533cb5911d0fe86cfd27187eb77e42cc5719cb7124,
                0x084292791fef8a2de0d2617e877fe8769bf81df0848ac54c1a02ea84289a2d0c,
                0x164f495708ce5e668303f5369920c7b223346f54ddce81dd65e29b28035352c8,
                0x24f8970af58f92f1edba22f8fa950de3f423307dc69c7e1ca026ac64d9155ad7,
                0x0c9ef83c1484d8fe1d0bff491d7dd24237f04df949be9e78f7b1c9baaf157e1b,
                0x21140ebf4a3a8fd06d22f440b05337fd47f9ef50ea48cbd101b038c3500aeb5b,
                0x287dc67a967ffe4925215678e4ee240fdc1eeeb3d5cca0dc2dcd421d61c63497,
                0x08bf1f8f96d3fdd9dc7f770a75c4f7971742ed0c1ef8bd676f59e3f034bbede2,
                0x0f1d886b93ffd7308b07791b0be78067a165f63556512d0e83d98a538c2bd0fd,
                0x1a17bf8d2e05b2f9722f6a6acc73efc384e3aeac7c1d1e68f92dad30bdccdce0,
                0x29647d1fd7116608b00a5b1aca74e3183fe9dff0d4dead1bae563a571a4be06f,
                0x0000000000000000000000000000000000000000000000000000000000000001,
                0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                0x03f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3,
                0x035ed813d62de4efaec2090398ec8f221801a5d6937e71583455587971f82372,
                0x0a9764b67db417148efa93189bc63edecad9416e5923f985233f439fe53d4368,
                0x03bb75e80a39e8afcee4f396477440968975a58b1a5f2222f48e7895bf4d5537,
                0x2d21805332ed46c9a5b57834e87c0395bc07a7c4ded911184427cc0c1cae8e37,
                0x018809491ccdf374352e3bc89f8cd1bb7e767653a46d5a7984e76a3ecc845a60,
                0x07c1dd5ff232cba92025ada9a706a4aa589f7835af8a8258ab0ae8ebd92969bd,
                0x0e22fda32802ba5b8e2c27a2a2a10964e1a9399c16540e2939545047c2d77c62
            ]
        );
        assert(result);
    }

    function testVerifyCarol() public view {
        bool result = verifier.verifyProof(
            [
                0x01c16ff2a1a1768ae54f6227eeb4b1d75a30bd4e5903a344b811086a97abd7a9,
                0x262a56b0984658af82b7bdc5ee162a173a5b4292693ef05f38ff82131c37f87d
            ],
            [
                [
                    0x19703205648c477e62e4d9930f150b8e637e63dd88f2e15e97a30e07e54b9ee3,
                    0x2cd6e7b1df66d4682e43ec8e078e34b6a62d4baa14ad89def0f101204c0655e8
                ],
                [
                    0x0321effea2ac7b5dd32b48d6ca909b717214bb82693a9f5671d00dd93164042a,
                    0x28309ec5da1acbae0af98b5b894d1f1bdef4aa1fc2228245311ec347d7583833
                ]
            ],
            [
                0x03d8e55483c4c9badbc2dae476f1b574e138db33483537890352b8bc9343ed71,
                0x1d3926bfc37027313855514eaaae7a897cd31f859b4f13c646851d98a6c3941d
            ],
            [
                0x03bb75e80a39e8afcee4f396477440968975a58b1a5f2222f48e7895bf4d5537,
                0x2d21805332ed46c9a5b57834e87c0395bc07a7c4ded911184427cc0c1cae8e37,
                0x278da9b32323bf8afa691001d5d20e2c5f96db21b18a2e22f28e5d5742992232,
                0x2cf9744859cdd3d29fd15057b7e3ebd2197a1af0bae650e5e40bfcd437dfd299,
                0x1cf1e6e4f9f4aa29430a9b08d51584f3194571178c0dde3f8d2edfef28cc2dac,
                0x26f532e67dc0880ff05b88fbe206ac8cccc7279c8ff6608070611e1feba80d34,
                0x2d86cbb6cb1e2c9fea0aa2e954c050a576a6389ff2a3ba5fb56c955acf5e7dd7,
                0x2baff49b2c25533429030682feba2055f0559010a353a305f477315cff26f857,
                0x1d84598a953f9a03e7683c81e3320d91cc7876ff7ed66698c7b5ad0e2d510f23,
                0x1b3340c7e2186338d97e8ecc5541067327a7ef1f5bd2f78d948f40ff8579a2f7,
                0x1432b7063b0637bb63abd4a09ca48e54124fa499463e1704a42ea1c19c69ee38,
                0x1c8fa3c18b2192bfb729a40931491b23f66d0ed5979123c5442bd5380757f83b,
                0x190fb1fccfbf63a4c683e6caf945cd90991bafd6eaa65b9192ed94bb44533176,
                0x1ecdc7e068d459804aee2bfe03654947ca95c740095904b90f97519df06179f7,
                0x0000000000000000000000000000000000000000000000000000000000000001,
                0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                0x03f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3,
                0x035ed813d62de4efaec2090398ec8f221801a5d6937e71583455587971f82372,
                0x0a9764b67db417148efa93189bc63edecad9416e5923f985233f439fe53d4368,
                0x03bb75e80a39e8afcee4f396477440968975a58b1a5f2222f48e7895bf4d5537,
                0x2d21805332ed46c9a5b57834e87c0395bc07a7c4ded911184427cc0c1cae8e37,
                0x201e86bdaa637b185b47b18ba21aa4bf8ab1b52379a8f78fc7566277e73e225c,
                0x00094c8c56a206d2294fa3987b2a4f34fcea8675aacf8bb993775d8856065c63,
                0x22bd22f26744b94655b17c01b74968b3f186a620413d3213c27db9b92fe192d0
            ]
        );
        assert(result);
    }

    function testVerifyAnother() public view {
        bool result = verifier.verifyProof(
            [
                0x28d135b95cf5fd448c0d8a57d9712b26db1dc9386592e5542caa0b4f1aacb3a9,
                0x1046779355dcafda52bbc54ee3ec922fc42b8dfd8d223fc7f0eeb3a44356fad4
            ],
            [
                [
                    0x1956785286b364f0e0594c1e8975e129ea9abef9179a5bebf1a1343b6c8e532c,
                    0x2c4abcae508007f22731132b7d0eeec9dd196cc72dd11016cd1b7b09a63d4aa3
                ],
                [
                    0x285957e089bb2cf46860ea8ebe5f5596d22cd1a84de28630db79a413a862c328,
                    0x0c608b4adc419501c3827b0bd39ece14ffa29cc918579effcddf06b721ad110b
                ]
            ],
            [
                0x0fc44ac1ec9d363db6b79b4b69114bcde462166c401aa8731a96c8b94b0843c1,
                0x288ac9d0b1a67189a706c90b5c2a247ac57d528dd710ccd796f028a6d06166b7
            ],
            [
                0x022fd3961ed281262dcafb6c31e3c77fd4a6336982af9017ac2230465ac24a54,
                0x0ba81f922d955aa669e2a11b0f08c43b34e3c2c4c4ee17380199a6231113e69b,
                0x25057bba975524a977d379c163cf6889694e454cb247828843b61c5e5e5079be,
                0x0f04937e5b6ccd689589bd4165cd7270bd9e4f3fad91c93b6f9066bcc5d23c77,
                0x2c856577c9aaac99ad47848306ea97e1f4273a22bfe895f88437e06e4f4de052,
                0x2faab5db1091e9be4aee0beb6239c30c3de4102c3f9c22fdf1f2cd1e21afeecc,
                0x1c82bff93fc6a3e25e8643afbe3750167a9c3e09a669008a2cb9ae14f63ab3c4,
                0x20a915b4cdb36d040e883238ca21b00a80a540ac28e74f55e35d6aa7016a5cf0,
                0x01db10892f18c5f9d43efc18a2b9ed73dba2bdfda32cf24a2ef72cfcc5fde94b,
                0x0c7c18bfe7b330116fd0430d62f48d2e51999575b81fae2a4284ff5c15f419b8,
                0x00df99e8b7bdad36ffb6231f404e1c95b152b70949c32b258c7325671fc48e9f,
                0x277cf20cb3e72d9b471222150b1be26d077eae866cb96a479e3d2490a07fc19a,
                0x02bdc1f2ff27ce2625e6793535750dca70297b800cf01836d269c6854998c21e,
                0x1610fa892e23cff5fa32a12eead0a796f26c24dee5412e0d4b6fc4435a436c5a,
                0x0000000000000000000000000000000000000000000000000000000000000001,
                0x119a1f9c0d66242ee746c34bc1a955c490b635d60d8399b349514aa43f3b1ae7,
                0x1dd68c1368fe554815d805a97a035d03713594b3c8074b2c215c67539cf974ee,
                0x0c93edd705466bb00c61dead122675905e1a51df9d2100f30e9857377b2238f7,
                0x21521569b71545efa48193aa7526836ff387a27111678fc40033407326f8dd66,
                0x022fd3961ed281262dcafb6c31e3c77fd4a6336982af9017ac2230465ac24a54,
                0x0ba81f922d955aa669e2a11b0f08c43b34e3c2c4c4ee17380199a6231113e69b,
                0x1df9fc3cdd38c341829ca312e213912df1c3257dc82c99cce9d9b5852d387b70,
                0x0e7f5649e7034bee546f84e1f71c092ab1597d25b95a0076cb3fdd88da080347,
                0x2e1bbc5cf7ed4ce9f2299eb1e27e5b1763550ffcb13b48640b4985a7e1394493
            ]
        );
        assert(result);
    }
}
