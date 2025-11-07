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
    uint256 constant alphax = 533463221635568900876474613179320146507100335368689636443123690405423666962;
    uint256 constant alphay = 3238362824771177119590660253268733963515637949289006952636822511948004610161;
    uint256 constant betax1 = 16541107702344851829328666318939829920578322899840215730804453714167826992411;
    uint256 constant betax2 = 18641532315752784057494748129569290795580154324156233076526002418393136695601;
    uint256 constant betay1 = 7130492600489801299278707044938512889283722930120377005090300974578302407423;
    uint256 constant betay2 = 21402348403558354628354549402600447290321639124266127469398546146565837797581;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 2523190678655433556776744037926242563998743454724276489928105324335407264550;
    uint256 constant deltax2 = 1740579062692209741999259701987495201734726383927764836107923370280011894150;
    uint256 constant deltay1 = 1069550510897126887721549744800863248587953089510719991871277724336156029761;
    uint256 constant deltay2 = 18508418210425327860998194278439088460590721365591246019442643423188598170046;

    uint256 constant IC0x = 19157318586508518019673635339960477669218571842327444267136865521385171516115;
    uint256 constant IC0y = 21338237983322955372209707297671831622707251941414077781810822955727302461491;

    uint256 constant IC1x = 9284162736474976161941332907821686011536118871084961069364113732676281736162;
    uint256 constant IC1y = 3423495818855114603945334968725803367115677620464573219357633300567273037861;

    uint256 constant IC2x = 2944391750388969988582977499803359499535639754388979703098413158498857433195;
    uint256 constant IC2y = 14486382776607334335557858094971909026111441901900724139998607943165568661559;

    uint256 constant IC3x = 19629812402764474536674189563185817165869572216289000255168662818655676152769;
    uint256 constant IC3y = 18466087450161934799964057956250333411089976871905007106392212774487257221073;

    uint256 constant IC4x = 1421193045452863236918296552278795507006434632840786670181549550408871757764;
    uint256 constant IC4y = 3425217570176042463177838709807688005323675156787473528327568263094247564375;

    uint256 constant IC5x = 6927011947393000399819754848745240384818262860351912573096568855794960656623;
    uint256 constant IC5y = 19999037979124216363622688861224739422757214406879046512730186575907825153949;

    uint256 constant IC6x = 19522728165611809234411346917277476068711006242148029225327573191102695589553;
    uint256 constant IC6y = 7597244206806727819432274687620670961666983355227562862518865539345725294978;

    uint256 constant IC7x = 14732291532370124324612625204127543348686980013475656938414730482802295260151;
    uint256 constant IC7y = 17263187175504858629897215091203947695054174097923393139296813800319328912042;

    uint256 constant IC8x = 18091203258156296603078552183173417588051640947309259042153359475116818897686;
    uint256 constant IC8y = 1001594739589869807897983879225418153373269650299514240727283895372917834956;

    uint256 constant IC9x = 7422253117609117490563597289528029510969072644340490305693366769677090702821;
    uint256 constant IC9y = 15195486435863200129805147566852813415425304824114371637898436192954937087700;

    uint256 constant IC10x = 11868631973738856259254480454851558583996754691178924913779778686377534066426;
    uint256 constant IC10y = 12893944474360412642820572142779777746069103693877028136478896055923554896471;

    uint256 constant IC11x = 21162345359914461442514990870014976954417071220313934363695185144745080402278;
    uint256 constant IC11y = 20836023792738186699618144945720816898203876405807831540623385004049505318178;

    uint256 constant IC12x = 18320961546829269212074119881658569910352624213394091441319694519207177897772;
    uint256 constant IC12y = 5511401804619474913592859740952082348638997113547425629687490576974308956810;

    uint256 constant IC13x = 4462234103348736201959924487612413503522761274805247275082099211080659760871;
    uint256 constant IC13y = 12797766444997542785669688760980683775301719967360963993560043383703568913009;

    uint256 constant IC14x = 20994928356054599037534706224210440355224313828879919622372432535324669287241;
    uint256 constant IC14y = 2456325094365162900575099420008428499691805996732590560191534380384605533607;

    uint256 constant IC15x = 3172327532250984194446627710462073046314890531881379383554664568913562296088;
    uint256 constant IC15y = 14354117643313409197791497729492100656614510071743913508689223354650537525580;

    uint256 constant IC16x = 655779726983994651554789459935019247752709201594828893851035340083293545877;
    uint256 constant IC16y = 20592633278296129348672746038434555376506649194250729023437416460119952778557;

    uint256 constant IC17x = 10962304756067701657683650944898864907088650471723650584345921177425313878005;
    uint256 constant IC17y = 9315596382712874430966991799724356733905980099917680465537504050601793945232;

    uint256 constant IC18x = 493321068449611966417475529968463173410270352026348386101521891469206975436;
    uint256 constant IC18y = 3455736740826675345780122438053525859396338429297911890123483420496566941177;

    uint256 constant IC19x = 7316050358284351567050646158349279134658853038538883937762888742635605572594;
    uint256 constant IC19y = 11638063312913261642864875868889202912974416819915733803318840748209436692790;

    uint256 constant IC20x = 18659990508307508343329026503718770695727605403972773119680430596061270053019;
    uint256 constant IC20y = 21598586171199943298654179052075985889713321400639695882205812411797077368993;

    uint256 constant IC21x = 7871751760391311265905632573636472990340271100188730147356119260360142372616;
    uint256 constant IC21y = 48385207140864035820941653286229448188451459256617961829041402408250713990;

    uint256 constant IC22x = 2634295315467091355207954456767284528084404544664925633652654845090754073248;
    uint256 constant IC22y = 19333655233411058691846539971421044672783612554086820728412820031148414081163;

    uint256 constant IC23x = 20886210904245406388351826253763785818426562768357140625626544285150755832774;
    uint256 constant IC23y = 9848396342846773139686861693738667422824326251622588720652331798997507898093;

    uint256 constant IC24x = 13431072037116102778805347650039873236990687696977072615351111220303680137251;
    uint256 constant IC24y = 21214126792165682667674642514176205680197614492644579293553281582366790681126;

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
