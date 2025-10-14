// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 3038128979742085162646492756039224278480357348788823642777105025067750904692;
    uint256 constant alphay  = 18791330549412233083335569352910477382507261548617206700695802939295918423166;
    uint256 constant betax1  = 7232835503769776115880822169172491828083235738066737798928082201965111959413;
    uint256 constant betax2  = 5403401374714223075323826162461870249664896553140813492723028084690037462364;
    uint256 constant betay1  = 21563273819685567598599001107556918348570298220313643129404339471928738076881;
    uint256 constant betay2  = 11718779972096211060044222605150532067013879420504470161622514508100545954838;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 21758036256000561495257312664047752002395074084032755590260195868406983887402;
    uint256 constant deltax2 = 12818822558813008566122417229253088065452286361735202638733501600305124545148;
    uint256 constant deltay1 = 7348333552055160513091945212812073042985150076371253867767746582346482704916;
    uint256 constant deltay2 = 2002882277055864080051598503729523015153425632534258408333916841922173995803;

    
    uint256 constant IC0x = 14591115595987663724184493935869947560489922347394210482642425202785710132143;
    uint256 constant IC0y = 12077252366621895911068588213533549797721422389605755617525483825394428009391;
    
    uint256 constant IC1x = 28885809895331135333859220243736851904366732587824463049813345638440227548;
    uint256 constant IC1y = 9237807876429145940318022696130625604497813553198778438301785061846547611908;
    
    uint256 constant IC2x = 7762386540103462986779370476692323033117449428959947350881817062596512448128;
    uint256 constant IC2y = 17636829347409078234361352781032966596114915093147781196940750886684841238599;
    
    uint256 constant IC3x = 11760586450511414218748588111362288721395757643891190517175080080385123121177;
    uint256 constant IC3y = 10832010331943999615748192789036158072602759400967802044451388259786822582514;
    
    uint256 constant IC4x = 19403085898359085174141241232859412135175561371485720911878483705177820975462;
    uint256 constant IC4y = 5743003954157634429232572971530890591591688746072439610771833970110088416476;
    
    uint256 constant IC5x = 5448056046840408164101486399897604708033948236438899588781504868694212980015;
    uint256 constant IC5y = 14647827506116198134393780145631890336539465038337104551261382480197335120169;
    
    uint256 constant IC6x = 11963955115673114772439147047616194810101297654380012250025794418085957454810;
    uint256 constant IC6y = 17097990702943438119419344239813227503963616778993973570373303979588638444663;
    
    uint256 constant IC7x = 19305794987190801626374417167708009890042445717013371119644333997678279996703;
    uint256 constant IC7y = 16668514049904546931146632588540837183095810425967028347682985721035537514262;
    
    uint256 constant IC8x = 9627720184351757029450334168357182529659555149963479678735723164615687596545;
    uint256 constant IC8y = 824918169423300954240411371271931247144521572762887001320686356131053401813;
    
    uint256 constant IC9x = 13752075471251535772237563505666562339289921237086320251813641406223685469680;
    uint256 constant IC9y = 2821353745262611758802893135750208979365762986895650324770429155599361756838;
    
    uint256 constant IC10x = 6323057467055374273889955505186022478121716205081160388392253728884742997870;
    uint256 constant IC10y = 13573049429169990943559100707637944277519122429277499083770021620272358685190;
    
    uint256 constant IC11x = 5903912120388560511227815358255038259023307240013512994155265934578911641664;
    uint256 constant IC11y = 3447571910934901250785167487589447525303399081486624777591503481527750785131;
    
    uint256 constant IC12x = 20560495439209533630957559135382218815207774376089560536625056482126437420996;
    uint256 constant IC12y = 2819810184107040204331870687397554854061269772558755466628085344023418829594;
    
    uint256 constant IC13x = 10859990446091204060945760793736867004189960750082308390575241753817112540470;
    uint256 constant IC13y = 6948763391082123161050695056929681906821659788929152484064249054659922354289;
    
    uint256 constant IC14x = 1164481851218628186014215506722870365626509378724760965197991237554362921305;
    uint256 constant IC14y = 7614380995377406828602071708960203568507065999665196166266559141810575318571;
    
    uint256 constant IC15x = 14568613201771529161419002761736628297616781031347221319020814880620834053345;
    uint256 constant IC15y = 15415158796982315122631406002509067668873155366091273305775116242413581525892;
    
    uint256 constant IC16x = 985234824822363890396688103493125605321465094513334865508104179569463059313;
    uint256 constant IC16y = 12038090093283591909631905419139464048201665608677467329915620776358461737849;
    
    uint256 constant IC17x = 2525562093010142345934686192446139822272808159642958222913704131884814928171;
    uint256 constant IC17y = 13594913204686587834957388431671487674743015158171790737316751039117377713079;
    
    uint256 constant IC18x = 6876428878336661689778506721019196518011162403185143830165934466963227255549;
    uint256 constant IC18y = 10274221146460697441328463106733318773476466895637635489994739385228414775179;
    
    uint256 constant IC19x = 3072166007111071000610213268898485977998104784980008224694723409539805410133;
    uint256 constant IC19y = 5695800892489134200557147543334872539566834136973432122373866365767106559400;
    
    uint256 constant IC20x = 12816387773795174888750222715632885667876480333069211930257898675111914378804;
    uint256 constant IC20y = 5393024378902146087505714272567042721509794866379192858919547386846422103340;
    
    uint256 constant IC21x = 8104900331644314402751955689924626383481615730569039546738590649825950158621;
    uint256 constant IC21y = 5944733146563515218951718778202877349458710257552935096772386249933697517646;
    
    uint256 constant IC22x = 11541724625945480317562247282855236679042609489179234103797757567069692760465;
    uint256 constant IC22y = 15379168239394302597881231041235643252691559848337360966131613009158998193606;
    
    uint256 constant IC23x = 10382867664092134427115530828854250192712125641575458893093951222771925122716;
    uint256 constant IC23y = 4333348476546612547847532837595291488565098246049619802827675649365439603253;
    
    uint256 constant IC24x = 14301418575062957739877951958405302961774698048829005096185125946370423660444;
    uint256 constant IC24y = 19511560420045242344798256893083816633731872198365870757868598782740300443147;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[24] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
