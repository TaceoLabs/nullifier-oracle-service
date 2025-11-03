// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {RpRegistry} from "../src/RpRegistry.sol";
import {BabyJubJub} from "../src/BabyJubJub.sol";
import {Groth16Verifier as Groth16VerifierKeyGen13} from "../src/Groth16VerifierKeyGen13.sol";
import {Groth16Verifier as Groth16VerifierNullifier} from "../src/Groth16VerifierNullifier.sol";
import {Types} from "../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract RpRegistryTest is Test {
    using Types for Types.BabyJubJubElement;

    uint256 public constant THRESHOLD = 2;
    uint256 public constant MAX_PEERS = 3;

    RpRegistry public rpRegistry;
    BabyJubJub public accumulator;
    Groth16VerifierKeyGen13 public verifierKeyGen;
    Groth16VerifierNullifier public verifierNullifier;
    ERC1967Proxy public proxy;

    address alice = address(0x1);
    address bob = address(0x2);
    address carol = address(0x3);
    address taceoAdmin = address(0x4);

    uint256 privateKeyAlice = 0x3bc78294cae1fe9e441b3c6a97fc4f7844b016ec9deb28787b2ec8a63812834;
    uint256 privateKeyBob = 0xb5aaa322223b7015e0ab2690ddad24a3e553bbea711dcdd0f30e2ea2ca6fdc;
    uint256 privateKeyCarol = 0x379ca5cd47470da7bcefb954d86cf4d409d25dd2d65c4e2280aa2bcfc4f1f4d;

    Types.BabyJubJubElement publicKeyAlice = Types.BabyJubJubElement({
        x: 0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
        y: 0x3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3
    });

    Types.BabyJubJubElement publicKeyBob = Types.BabyJubJubElement({
        x: 0x35ed813d62de4efaec2090398ec8f221801a5d6937e71583455587971f82372,
        y: 0xa9764b67db417148efa93189bc63edecad9416e5923f985233f439fe53d4368
    });

    Types.BabyJubJubElement publicKeyCarol = Types.BabyJubJubElement({
        x: 0x3bb75e80a39e8afcee4f396477440968975a58b1a5f2222f48e7895bf4d5537,
        y: 0x2d21805332ed46c9a5b57834e87c0395bc07a7c4ded911184427cc0c1cae8e37
    });

    uint256 commCoeffsAlice = 0x6fc7aa21491e4b6878290f06958efa50de23e427d7b4f17b49b8da6191ad41f;

    uint256 commCoeffsBob = 0x84292791fef8a2de0d2617e877fe8769bf81df0848ac54c1a02ea84289a2d0c;

    uint256 commCoeffsCarol = 0x1cf1e6e4f9f4aa29430a9b08d51584f3194571178c0dde3f8d2edfef28cc2dac;

    Types.BabyJubJubElement commShareAlice = Types.BabyJubJubElement({
        x: 0x1713acbc11e0f0fdaebbcedceed52e57abf30f2b8c435f013ce0756e4377f097,
        y: 0x28145c47c630ed060a7f10ea3d727b9bc0d249796172c2bcb58b836d1e3d4bd4
    });

    Types.BabyJubJubElement commShareBob = Types.BabyJubJubElement({
        x: 0x23c80416edd379bde086351fc0169cfa69adff2c0f0ab04ca9622b099e597489,
        y: 0x130cf58590a10bdf2b75d0533cb5911d0fe86cfd27187eb77e42cc5719cb7124
    });

    Types.BabyJubJubElement commShareCarol = Types.BabyJubJubElement({
        x: 0x278da9b32323bf8afa691001d5d20e2c5f96db21b18a2e22f28e5d5742992232,
        y: 0x2cf9744859cdd3d29fd15057b7e3ebd2197a1af0bae650e5e40bfcd437dfd299
    });

    Types.EcDsaPubkeyCompressed ecdsaPubKey = Types.EcDsaPubkeyCompressed({x: bytes32(0), yParity: 2});

    function setUp() public {
        accumulator = new BabyJubJub();
        verifierKeyGen = new Groth16VerifierKeyGen13();
        verifierNullifier = new Groth16VerifierNullifier();
        // Deploy implementation
        RpRegistry implementation = new RpRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector, taceoAdmin, verifierKeyGen, verifierNullifier, accumulator
        );
        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        rpRegistry = RpRegistry(address(proxy));

        // register participants for runs later
        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;
        rpRegistry.registerOprfPeers(peerAddresses);
    }

    function testConstructedCorrectly() public {
        // Deploy implementation
        RpRegistry implementation = new RpRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector, taceoAdmin, verifierKeyGen, verifierNullifier, accumulator
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        RpRegistry rpRegistryTest = RpRegistry(address(proxyTest));

        assertEq(rpRegistryTest.keygenAdmin(), taceoAdmin);
        assertEq(address(rpRegistryTest.keyGenVerifier()), address(verifierKeyGen));
        assertEq(address(rpRegistryTest.nullifierVerifier()), address(verifierNullifier));
        assertEq(address(rpRegistryTest.accumulator()), address(accumulator));
        assertEq(rpRegistryTest.threshold(), 2);
        assertEq(rpRegistryTest.numPeers(), 3);
        assert(!rpRegistryTest.isContractReady());

        // TODO call other functions to check that it reverts correctly
    }

    function testRegisterParticipants() public {
        // Deploy implementation
        RpRegistry implementation = new RpRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector, taceoAdmin, verifierKeyGen, verifierNullifier, accumulator
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        RpRegistry rpRegistryTest = RpRegistry(address(proxyTest));

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;

        // check that not ready
        assert(!rpRegistryTest.isContractReady());
        rpRegistryTest.registerOprfPeers(peerAddresses);

        // check that ready after call
        assert(rpRegistryTest.isContractReady());

        // check that parties can read their partyID
        vm.prank(alice);
        uint256 aliceId = rpRegistryTest.checkIsParticipantAndReturnPartyId();
        assertEq(aliceId, 0);
        vm.stopPrank();

        vm.prank(bob);
        uint256 bobId = rpRegistryTest.checkIsParticipantAndReturnPartyId();
        assertEq(bobId, 1);
        vm.stopPrank();

        vm.prank(carol);
        uint256 carolId = rpRegistryTest.checkIsParticipantAndReturnPartyId();
        assertEq(carolId, 2);
        vm.stopPrank();

        // check that taceo is not a participant
        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(RpRegistry.NotAParticipant.selector));
        rpRegistryTest.checkIsParticipantAndReturnPartyId();
        vm.stopPrank();
    }

    function testRegisterParticipantsNotTACEO() public {
        // Deploy implementation
        RpRegistry implementation = new RpRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector, taceoAdmin, verifierKeyGen, verifierNullifier, accumulator
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        RpRegistry rpRegistryTest = RpRegistry(address(proxyTest));

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;
        // check that not ready
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        rpRegistryTest.registerOprfPeers(peerAddresses);
    }

    function testRegisterParticipantsTwice() public {
        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;
        // check that not ready
        vm.expectRevert(abi.encodeWithSelector(RpRegistry.AlreadySubmitted.selector));
        rpRegistry.registerOprfPeers(peerAddresses);
    }

    function testRegisterParticipantsWrongNumberKeys() public {
        // Deploy implementation
        RpRegistry implementation = new RpRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector, taceoAdmin, verifierKeyGen, verifierNullifier, accumulator
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        RpRegistry rpRegistryTest = RpRegistry(address(proxyTest));

        address[] memory peerAddressesWrong = new address[](2);
        peerAddressesWrong[0] = alice;
        peerAddressesWrong[1] = bob;

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.UnexpectedAmountPeers.selector, 3));
        rpRegistryTest.registerOprfPeers(peerAddressesWrong);
    }

    function testInitKeyGenResubmit() public {
        vm.prank(taceoAdmin);
        rpRegistry.initKeyGen(0, ecdsaPubKey);
        vm.expectRevert(abi.encodeWithSelector(RpRegistry.AlreadySubmitted.selector));
        vm.prank(taceoAdmin);
        rpRegistry.initKeyGen(0, ecdsaPubKey);
    }

    function testInitKeyGenParityWrong() public {
        Types.EcDsaPubkeyCompressed memory ecdsaPubKeyBroken = Types.EcDsaPubkeyCompressed({x: bytes32(0), yParity: 1});

        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(RpRegistry.BadContribution.selector));
        rpRegistry.initKeyGen(1, ecdsaPubKeyBroken);
    }

    function testE2E() public {
        uint128 rpId = 42;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound1(rpId, THRESHOLD);
        rpRegistry.initKeyGen(rpId, ecdsaPubKey);
        vm.stopPrank();

        // do round 1 contributions
        vm.prank(bob);
        rpRegistry.addRound1Contribution(
            rpId,
            Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
        );
        vm.stopPrank();

        vm.prank(alice);
        rpRegistry.addRound1Contribution(
            rpId,
            Types.Round1Contribution({
                commShare: commShareAlice, commCoeffs: commCoeffsAlice, ephPubKey: publicKeyAlice
            })
        );
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound2(rpId);
        rpRegistry.addRound1Contribution(
            rpId,
            Types.Round1Contribution({
                commShare: commShareCarol, commCoeffs: commCoeffsCarol, ephPubKey: publicKeyCarol
            })
        );
        vm.stopPrank();

        // do round 2 contributions

        vm.prank(bob);
        rpRegistry.addRound2Contribution(rpId, bobRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        rpRegistry.addRound2Contribution(rpId, aliceRound2Contribution());
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound3(rpId);
        vm.prank(carol);
        rpRegistry.addRound2Contribution(rpId, carolRound2Contribution());
        vm.stopPrank();

        // do round 3 contributions
        vm.prank(alice);
        rpRegistry.addRound3Contribution(rpId);
        vm.stopPrank();

        vm.prank(bob);
        rpRegistry.addRound3Contribution(rpId);
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenFinalize(rpId);
        vm.prank(carol);
        rpRegistry.addRound3Contribution(rpId);
        vm.stopPrank();

        // check that the computed nullifier is correct
        Types.RpMaterial memory material = rpRegistry.getRpMaterial(rpId);
        assertEq(material.nullifierKey.x, 2197751895809799734146001567623507872025142095924791991243994059456432106738);
        assertEq(material.nullifierKey.y, 17752307105958841504133705104840128793511849993452913074787269028121192628329);
        assertEq(material.ecdsaKey.x, bytes32(0));
        assertEq(material.ecdsaKey.yParity, 2);
    }
}

function aliceProof() pure returns (Types.Groth16Proof memory) {
    return Types.Groth16Proof({
        pA: [
            0x0730d45e94d07a4b54f225fd0d0b89bae66f89d8731f9cc50f6a87e072871ea6,
            0x2f20d1bdef6a6417b268bd954cd8e1d4be12d4cd51fa05eb9b76b990f931fe7f
        ],
        pB: [
            [
                0x19a178b3af5e560e9563744674e8deef661468e0b64848670b395a1b98d93e3c,
                0x047d859e0c4c151d55a4a983a33e7c15df8ef3a2d3c77a8ac5049238e3305788
            ],
            [
                0x0ed5a75f3e1d43fa555c9525912f10d7d30a344447ea6724df6df995615e0c64,
                0x0570c2f37467f1eaf8f351065545942b2624fabcb908a1ea483a4c2c913ef872
            ]
        ],
        pC: [
            0x00176fd3aa2c901a0b49edd8a05fbb7aae532d5e36c355939f9cdc617a63e5d3,
            0x21ea25e4273c82581c7bc0040f61a6b1ddc0de7cc86fda106554880bacf57c47
        ]
    });
}

function bobProof() pure returns (Types.Groth16Proof memory) {
    return Types.Groth16Proof({
        pA: [
            0x1775f93c20a9d661e64c77d5b926242dc180f504878e185b3df0e2ae078c66dc,
            0x26d55220a7396de0477d01d9e72163d74b6b3b1642ed262bbcfce6ec250739ff
        ],
        pB: [
            [
                0x2dc70a7ecc35079e827c98b9fb27e67c0483fe924b93e8d07932791981c98509,
                0x2dec711659f448b6f6a483e347ea64c75b075f3fefb3d9a0f0792eb8ae171c1b
            ],
            [
                0x138101131f156b73f0a872f28b8ebe59e87d876462a64cf9af1f542be021f727,
                0x16523fe5288ca03c732ea124ed345a31da9124c357e792bcde2f6ae0e2119318
            ]
        ],
        pC: [
            0x194a217452c303c8c4c60ffa9b9077d54d8aeb70b50ddbe52e63f185f8a3b271,
            0x0930f3480ecb9d0e358348e644c93fe60dd31f991d1cdcc241b550b973db6715
        ]
    });
}

function carolProof() pure returns (Types.Groth16Proof memory) {
    return Types.Groth16Proof({
        pA: [
            0x01c16ff2a1a1768ae54f6227eeb4b1d75a30bd4e5903a344b811086a97abd7a9,
            0x262a56b0984658af82b7bdc5ee162a173a5b4292693ef05f38ff82131c37f87d
        ],
        pB: [
            [
                0x19703205648c477e62e4d9930f150b8e637e63dd88f2e15e97a30e07e54b9ee3,
                0x2cd6e7b1df66d4682e43ec8e078e34b6a62d4baa14ad89def0f101204c0655e8
            ],
            [
                0x0321effea2ac7b5dd32b48d6ca909b717214bb82693a9f5671d00dd93164042a,
                0x28309ec5da1acbae0af98b5b894d1f1bdef4aa1fc2228245311ec347d7583833
            ]
        ],
        pC: [
            0x03d8e55483c4c9badbc2dae476f1b574e138db33483537890352b8bc9343ed71,
            0x1d3926bfc37027313855514eaaae7a897cd31f859b4f13c646851d98a6c3941d
        ]
    });
}

function aliceRound2Contribution() pure returns (Types.Round2Contribution memory) {
    Types.SecretGenCiphertext[] memory ciphers = new Types.SecretGenCiphertext[](3);
    ciphers[0].cipher = 0x28bb5603f454ca0e93975292a64b5e2627508939c34f75110b1f564b5c573700;
    ciphers[0].nonce = 0x2e0e33932fed970f0a6502ccdbd31d9f53d869dd97047e8163b61b64ea184893;
    ciphers[0].commitment = Types.BabyJubJubElement({
        x: 0x1d0c22e0b65e28a2dda5d1f7963f17576bb6e1ac6fda44d1f64688c9f4fd10d3,
        y: 0x2918af65f63e3619ac5cbcc3771e124f8fdaa06b73e45a84472999dbf2115e8e
    });

    ciphers[1].cipher = 0x12297ee0bfbd08ff417e17f98ceb6fd1fd0ebf7591dfc240cf863ee809f0fd74;
    ciphers[1].nonce = 0x046dc1740048f99098f97b9a74f725bc21ae5248eeb9e6385dbdc0b5e128c558;
    ciphers[1].commitment = Types.BabyJubJubElement({
        x: 0x25f159ef60c19fa55bdeeac713eab1bc69e41f7e9079f7bffdd0ef7d7381166a,
        y: 0x1a53af8466e5d476a6183f57ccfd6f1ed98729b972a40459c317547a390ad20d
    });

    ciphers[2].cipher = 0x11465b22b395b507b15fd06b33eb1074f067f9ba6638aca490cdfceef16fc3c0;
    ciphers[2].nonce = 0x15819576a5b57223acfbc67cc5af75400ebefa3a418e76d13de46e259e363171;
    ciphers[2].commitment = Types.BabyJubJubElement({
        x: 0x0e20e6c71ff0732a2cc47e78e55e1dca63dadf085b756a12e8cf384097cbdab2,
        y: 0x20bb39169676c06bd11bc45475ca73499e5e1bd6ef5934908be9b1e7ed261f93
    });

    return Types.Round2Contribution({proof: aliceProof(), ciphers: ciphers});
}

function bobRound2Contribution() pure returns (Types.Round2Contribution memory) {
    Types.SecretGenCiphertext[] memory ciphers = new Types.SecretGenCiphertext[](3);
    ciphers[0].cipher = 0x164f495708ce5e668303f5369920c7b223346f54ddce81dd65e29b28035352c8;
    ciphers[0].nonce = 0x018809491ccdf374352e3bc89f8cd1bb7e767653a46d5a7984e76a3ecc845a60;
    ciphers[0].commitment = Types.BabyJubJubElement({
        x: 0x21140ebf4a3a8fd06d22f440b05337fd47f9ef50ea48cbd101b038c3500aeb5b,
        y: 0x287dc67a967ffe4925215678e4ee240fdc1eeeb3d5cca0dc2dcd421d61c63497
    });

    ciphers[1].cipher = 0x24f8970af58f92f1edba22f8fa950de3f423307dc69c7e1ca026ac64d9155ad7;
    ciphers[1].nonce = 0x07c1dd5ff232cba92025ada9a706a4aa589f7835af8a8258ab0ae8ebd92969bd;
    ciphers[1].commitment = Types.BabyJubJubElement({
        x: 0x08bf1f8f96d3fdd9dc7f770a75c4f7971742ed0c1ef8bd676f59e3f034bbede2,
        y: 0x0f1d886b93ffd7308b07791b0be78067a165f63556512d0e83d98a538c2bd0fd
    });

    ciphers[2].cipher = 0x0c9ef83c1484d8fe1d0bff491d7dd24237f04df949be9e78f7b1c9baaf157e1b;
    ciphers[2].nonce = 0x0e22fda32802ba5b8e2c27a2a2a10964e1a9399c16540e2939545047c2d77c62;
    ciphers[2].commitment = Types.BabyJubJubElement({
        x: 0x1a17bf8d2e05b2f9722f6a6acc73efc384e3aeac7c1d1e68f92dad30bdccdce0,
        y: 0x29647d1fd7116608b00a5b1aca74e3183fe9dff0d4dead1bae563a571a4be06f
    });

    return Types.Round2Contribution({proof: bobProof(), ciphers: ciphers});
}

function carolRound2Contribution() pure returns (Types.Round2Contribution memory) {
    Types.SecretGenCiphertext[] memory ciphers = new Types.SecretGenCiphertext[](3);
    ciphers[0].cipher = 0x26f532e67dc0880ff05b88fbe206ac8cccc7279c8ff6608070611e1feba80d34;
    ciphers[0].nonce = 0x201e86bdaa637b185b47b18ba21aa4bf8ab1b52379a8f78fc7566277e73e225c;
    ciphers[0].commitment = Types.BabyJubJubElement({
        x: 0x1d84598a953f9a03e7683c81e3320d91cc7876ff7ed66698c7b5ad0e2d510f23,
        y: 0x1b3340c7e2186338d97e8ecc5541067327a7ef1f5bd2f78d948f40ff8579a2f7
    });

    ciphers[1].cipher = 0x2d86cbb6cb1e2c9fea0aa2e954c050a576a6389ff2a3ba5fb56c955acf5e7dd7;
    ciphers[1].nonce = 0x00094c8c56a206d2294fa3987b2a4f34fcea8675aacf8bb993775d8856065c63;
    ciphers[1].commitment = Types.BabyJubJubElement({
        x: 0x1432b7063b0637bb63abd4a09ca48e54124fa499463e1704a42ea1c19c69ee38,
        y: 0x1c8fa3c18b2192bfb729a40931491b23f66d0ed5979123c5442bd5380757f83b
    });

    ciphers[2].cipher = 0x2baff49b2c25533429030682feba2055f0559010a353a305f477315cff26f857;
    ciphers[2].nonce = 0x22bd22f26744b94655b17c01b74968b3f186a620413d3213c27db9b92fe192d0;
    ciphers[2].commitment = Types.BabyJubJubElement({
        x: 0x190fb1fccfbf63a4c683e6caf945cd90991bafd6eaa65b9192ed94bb44533176,
        y: 0x1ecdc7e068d459804aee2bfe03654947ca95c740095904b90f97519df06179f7
    });

    return Types.Round2Contribution({proof: carolProof(), ciphers: ciphers});
}
