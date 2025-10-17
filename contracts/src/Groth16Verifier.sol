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
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax = 4299136294996074878855472481952809192952014442242078882593357468779562426189;
    uint256 constant alphay = 20192434946886366164628711860108987242811748661689986148944690529039815990929;
    uint256 constant betax1 = 19034047418490884457516103940196789750180981641423486466232437010345189978012;
    uint256 constant betax2 = 10046304110360358317261110002653112506295323706639307100014919070698095648085;
    uint256 constant betay1 = 14807519307384673610795542928279481444327315824198037520580318533219025401153;
    uint256 constant betay2 = 15209884787870626913278341544605497566199736685289831030324406276899576743686;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant deltax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant deltay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant deltay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

    uint256 constant IC0x = 19747157602260061484973947195573598102776737799567070262696227824461806600252;
    uint256 constant IC0y = 18753151806286269016187936008164159281567542291337496616664126992596241203341;

    uint256 constant IC1x = 10604509787834590719467118652713082107200065875138175162805771257461530964846;
    uint256 constant IC1y = 18973810377660888624575549674149623270218838799903210972304354138017125666069;

    uint256 constant IC2x = 10105503964364316304774297774441365378049567227192809975371063218816778434357;
    uint256 constant IC2y = 19921209666783684249267486274560970407531984972308638364558627032523142583187;

    uint256 constant IC3x = 11628819390121571664274728586303966001224255831780459143006217463440724734528;
    uint256 constant IC3y = 21275782687034454547296844595621188212637563936213310885975877781149514917319;

    uint256 constant IC4x = 10520750674040816330356956397126303249342641268573059324718997958943396740701;
    uint256 constant IC4y = 9667872345433495045970985765845720807922907239659717083825075882859724370048;

    uint256 constant IC5x = 2500156064823547439740975977066186751775759985524340249487052329060126481497;
    uint256 constant IC5y = 4743498568456040859587329313815363812215442901199267395546842894611221505186;

    uint256 constant IC6x = 13159720562235144094106098925757763460817855267488722896515152210102488626549;
    uint256 constant IC6y = 20599959618177908674773958980991165847144638476136184774477694947306345614644;

    uint256 constant IC7x = 8580562044923153088565834120233925456946023298766032233937507613894762214009;
    uint256 constant IC7y = 16859313879008212130946680367306140930983055120327573370659049727967423148215;

    uint256 constant IC8x = 13341543206450280842180914184790932454089457188318677076519760301082099190274;
    uint256 constant IC8y = 4528752937577998290060660155327727536657080592387130192104372341068778202720;

    uint256 constant IC9x = 19387144899555505885124734764386014753276651191635929578139411106419803116053;
    uint256 constant IC9y = 2245788968219368460567593806728305950105605947860644932276365236987624712200;

    uint256 constant IC10x = 20676486875074284504395252404288737876822502615564387342996404269830691102725;
    uint256 constant IC10y = 2589264750862614918447054473352138274057949652109903174342121264872196084478;

    uint256 constant IC11x = 10017906851707184892776955095294950889070526595946251661441441571468720486665;
    uint256 constant IC11y = 8759581955524781478430636074244169707088270326271459438649914770542929711455;

    uint256 constant IC12x = 20308960114174563511122213161424424445803189673012042740046234093123669890485;
    uint256 constant IC12y = 3570397976118029058942211276178007686039837747228819296351775108817742076205;

    uint256 constant IC13x = 1243101106855570304053180370894277645619900504151153106655783565643019243586;
    uint256 constant IC13y = 6394435789301934196257692425783170276735456544726945828002337011970407009443;

    uint256 constant IC14x = 17361457776652357059898725916033621319394832616290676692141164228774631494267;
    uint256 constant IC14y = 3228948539845444371900531343026868866805156974422992520415098111770774526825;

    uint256 constant IC15x = 10545374868805381241902168067130141967286374766794351715937930906970511021100;
    uint256 constant IC15y = 21635849448639155316485450529457859682969919534695512859971373011722828511104;

    uint256 constant IC16x = 11545804792234649252003815074693867929070498840750071602491670854977006332724;
    uint256 constant IC16y = 19179254499116549403240592480983305235457641437463566027278601645140929944467;

    uint256 constant IC17x = 12016766539281648130542262994756956658921891143608241009328658967326364813044;
    uint256 constant IC17y = 4552858372497524887393970965001702707967106401251141479454808914137589993887;

    uint256 constant IC18x = 19594947159408075911254691431052126653887930109202205954898288272377470426627;
    uint256 constant IC18y = 543423436775476863052890374142724391340746019590942011373575698902394156168;

    uint256 constant IC19x = 183025870351715362354591753398128366566498384222031036997856053600735781894;
    uint256 constant IC19y = 784119065038414932016679805989973532728675940438334632281419277315917201003;

    uint256 constant IC20x = 10764021238353133727638439420333707625343476027187080726070854728625602903271;
    uint256 constant IC20y = 6398209594681912356039899641396205785594302657183317068925240382420335128500;

    uint256 constant IC21x = 16823654982666308335875287650674998808365604589040376842988359894748425758224;
    uint256 constant IC21y = 1513736664673455722639460476933126085942174038280037824213534020358082608901;

    uint256 constant IC22x = 20386582702367627130443393508962945945037069367567629802011868146724888403374;
    uint256 constant IC22y = 6029404950143480469441726855671212901598347591885185690751702445289890540792;

    uint256 constant IC23x = 16524074086095609844894562714742485996460942371214190518180957629939349761133;
    uint256 constant IC23y = 18934181371185804273944245680705378048244831554684761200773562157640471082413;

    uint256 constant IC24x = 5320920610050548932265221284725801203522603168837612531284696136207633285389;
    uint256 constant IC24y = 19417201581709078533984872845361009017176153733014824036542433846471020621105;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[24] calldata _pubSignals
    ) public view returns (bool) {
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
