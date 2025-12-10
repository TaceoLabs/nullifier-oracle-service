// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {BabyJubJub} from "../src/BabyJubJub.sol";

contract BabyJubJubTest is Test {
    BabyJubJub public babyJubJub;

    uint256 constant GEN_X = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    uint256 constant GEN_Y = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    uint256 constant TWO_G_X = 10031262171927540148667355526369034398030886437092045105752248699557385197826;
    uint256 constant TWO_G_Y = 633281375905621697187330766174974863687049529291089048651929454608812697683;

    uint256 constant THREE_G_X = 2763488322167937039616325905516046217694264098671987087929565332380420898366;
    uint256 constant THREE_G_Y = 15305195750036305661220525648961313310481046260814497672243197092298550508693;

    function setUp() public {
        babyJubJub = new BabyJubJub();
    }

    function testIdentityPoint() public view {
        assertTrue(babyJubJub.isOnCurve(0, 1));
    }

    function testGeneratorOnCurve() public view {
        assertTrue(babyJubJub.isOnCurve(GEN_X, GEN_Y));
    }

    function doSingleLagrangeCheckDeg1(uint8[2] memory ins, uint256[3] memory should) private view {
        uint256[] memory cast = new uint256[](2);
        uint256[] memory shouldResult = new uint256[](3);
        for (uint256 i = 0; i < 2; ++i) {
            cast[i] = uint256(ins[i]);
        }
        for (uint256 i = 0; i < 3; ++i) {
            shouldResult[i] = should[i];
        }
        uint256[] memory isResult = babyJubJub.computeLagrangeCoefficiants(cast, 2, 3);
        assertEq(isResult, shouldResult);
    }

    function doSingleLagrangeCheckDeg2(uint8[3] memory ins, uint256[5] memory should) private view {
        uint256[] memory cast = new uint256[](3);
        uint256[] memory shouldResult = new uint256[](5);
        for (uint256 i = 0; i < 3; ++i) {
            cast[i] = uint256(ins[i]);
        }
        for (uint256 i = 0; i < 5; ++i) {
            shouldResult[i] = should[i];
        }
        uint256[] memory isResult = babyJubJub.computeLagrangeCoefficiants(cast, 3, 5);
        assertEq(isResult, shouldResult);
    }

    function testLagrangeCoeffsDegree2() public view {
        doSingleLagrangeCheckDeg1(
            [0, 1], [2, 2736030358979909402780800718157159386076813972158567259200215660948447373040, 0]
        );
        doSingleLagrangeCheckDeg1(
            [0, 2],
            [
                1368015179489954701390400359078579693038406986079283629600107830474223686522,
                0,
                1368015179489954701390400359078579693038406986079283629600107830474223686520
            ]
        );
        doSingleLagrangeCheckDeg1(
            [1, 0], [2, 2736030358979909402780800718157159386076813972158567259200215660948447373040, 0]
        );
        doSingleLagrangeCheckDeg1(
            [1, 2], [0, 3, 2736030358979909402780800718157159386076813972158567259200215660948447373039]
        );
        doSingleLagrangeCheckDeg1(
            [2, 0],
            [
                1368015179489954701390400359078579693038406986079283629600107830474223686522,
                0,
                1368015179489954701390400359078579693038406986079283629600107830474223686520
            ]
        );
        doSingleLagrangeCheckDeg1(
            [2, 1], [0, 3, 2736030358979909402780800718157159386076813972158567259200215660948447373039]
        );
    }

    function testLagrangeCoeffsDegree3() public view {
        doSingleLagrangeCheckDeg2(
            [0, 1, 2], [3, 2736030358979909402780800718157159386076813972158567259200215660948447373038, 1, 0, 0]
        );
        doSingleLagrangeCheckDeg2(
            [2, 1, 4], [0, 5, 2736030358979909402780800718157159386076813972158567259200215660948447373036, 0, 1]
        );
        doSingleLagrangeCheckDeg2(
            [1, 3, 0],
            [
                912010119659969800926933572719053128692271324052855753066738553649482457683,
                2736030358979909402780800718157159386076813972158567259200215660948447373039,
                0,
                1824020239319939601853867145438106257384542648105711506133477107298964915361,
                0
            ]
        );
        doSingleLagrangeCheckDeg2(
            [0, 4, 2],
            [
                342003794872488675347600089769644923259601746519820907400026957618555921632,
                0,
                684007589744977350695200179539289846519203493039641814800053915237111843259,
                0,
                1710018974362443376738000448848224616298008732599104537000134788092779608151
            ]
        );
    }

    function testAddIdentity() public view {
        (uint256 x, uint256 y) = babyJubJub.add(0, 1, GEN_X, GEN_Y);
        assertEq(x, GEN_X);
        assertEq(y, GEN_Y);
    }

    function testAddGeneratorToItself() public view {
        (uint256 x, uint256 y) = babyJubJub.add(GEN_X, GEN_Y, GEN_X, GEN_Y);
        assertTrue(babyJubJub.isOnCurve(x, y));
        assertEq(x, TWO_G_X);
        assertEq(y, TWO_G_Y);
    }

    function testThreeTimes() public view {
        // 2*Generator by adding generator to itself
        (uint256 twoGx, uint256 twoGy) = babyJubJub.add(GEN_X, GEN_Y, GEN_X, GEN_Y);
        assertTrue(babyJubJub.isOnCurve(twoGx, twoGy));

        // Add generator + 2*generator to get 3*generator
        (uint256 threeGx, uint256 threeGy) = babyJubJub.add(GEN_X, GEN_Y, twoGx, twoGy);

        assertTrue(babyJubJub.isOnCurve(threeGx, threeGy));

        // Result should be different from both G and 2G
        assertTrue(threeGx != GEN_X || threeGy != GEN_Y);
        assertTrue(threeGx != twoGx || threeGy != twoGy);
        assertEq(threeGx, THREE_G_X);
        assertEq(threeGy, THREE_G_Y);
    }

    function testAddProjective() public view {
        uint256 x1 = 0;
        uint256 y1 = 1;
        uint256 t1 = 0;
        uint256 z1 = 1;

        uint256 x_kat1 = 2585013507242167102053568165755983650036811197698092260427036393667384073640;
        uint256 y_kat1 = 17439700738620329094074558196602008725531527645854103253457508274780729509178;

        uint256 x_kat2 = 16523095451005845378744871153186158172876773243913944605517223077126589763540;
        uint256 y_kat2 = 11395262298012017320039549102391546506375388353629184484925398200855215733632;

        uint256 x_kat3 = 13129558932074034887952119028896710108787924558103074500822124578701924232182;
        uint256 y_kat3 = 18418091431360366207558885589808338522336734072423030683885536759921650456300;

        uint256 x_kat4 = 19542872799279750368327332961592826852517520780375969478492096874027299559538;
        uint256 y_kat4 = 20237708949215360669094301572811104730197019148139884458681693214501806066578;

        (uint256 x_res_kat1, uint256 y_res_kat1, uint256 t_res_kat1, uint256 z_res_kat1) =
            babyJubJub.addProjective(x1, y1, t1, z1, 0, 1);
        (uint256 x_affine_kat1, uint256 y_affine_kat1) =
            babyJubJub.toAffine(x_res_kat1, y_res_kat1, t_res_kat1, z_res_kat1);
        assertEq(x_affine_kat1, 0);
        assertEq(y_affine_kat1, 1);

        (uint256 x_res_kat2, uint256 y_res_kat2, uint256 t_res_kat2, uint256 z_res_kat2) =
            babyJubJub.addProjective(x_res_kat1, y_res_kat1, t_res_kat1, z_res_kat1, x_kat1, y_kat1);

        (uint256 x_affine_kat2, uint256 y_affine_kat2) =
            babyJubJub.toAffine(x_res_kat2, y_res_kat2, t_res_kat2, z_res_kat2);
        assertEq(x_affine_kat2, 2585013507242167102053568165755983650036811197698092260427036393667384073640);
        assertEq(y_affine_kat2, 17439700738620329094074558196602008725531527645854103253457508274780729509178);

        // now just add the rest of the points and check the final result
        (uint256 x_res_kat3, uint256 y_res_kat3, uint256 t_res_kat3, uint256 z_res_kat3) =
            babyJubJub.addProjective(x_res_kat2, y_res_kat2, t_res_kat2, z_res_kat2, x_kat2, y_kat2);

        (uint256 x_res_kat4, uint256 y_res_kat4, uint256 t_res_kat4, uint256 z_res_kat4) =
            babyJubJub.addProjective(x_res_kat3, y_res_kat3, t_res_kat3, z_res_kat3, x_kat3, y_kat3);

        (uint256 x_res_kat5, uint256 y_res_kat5, uint256 t_res_kat5, uint256 z_res_kat5) =
            babyJubJub.addProjective(x_res_kat4, y_res_kat4, t_res_kat4, z_res_kat4, x_kat4, y_kat4);

        (uint256 x_final, uint256 y_final) = babyJubJub.toAffine(x_res_kat5, y_res_kat5, t_res_kat5, z_res_kat5);

        assertEq(x_final, 3658205807373373403783720572087030159367827012475349690027485513646047319095);
        assertEq(y_final, 13805961561979959184760556802896935268170915149201310889981879759954972423256);

        // add infinity for good measure
        (uint256 x_res_kat6, uint256 y_res_kat6, uint256 t_res_kat6, uint256 z_res_kat6) =
            babyJubJub.addProjective(x_res_kat5, y_res_kat5, t_res_kat5, z_res_kat5, 0, 1);
        (uint256 x_final_inf, uint256 y_final_inf) = babyJubJub.toAffine(x_res_kat6, y_res_kat6, t_res_kat6, z_res_kat6);

        assertEq(x_final_inf, x_final);
        assertEq(y_final_inf, y_final);
    }

    function testDoubleTwistedEdwards() public view {
        uint256 x_kat = 4637114908645349293314290093633489884625737925118392128630470256457586767218;
        uint256 y_kat = 7702897701668481564490177408361351787199791082682511447039848285746674581137;
        uint256 z_kat = 18908571007685925892997521016563680288958149020760971328391668907056652481525;

        (uint256 x_kat0, uint256 y_kat0, uint256 t_kat0, uint256 z_kat0) = babyJubJub.doubleTwistedEdwards(0, 1, 1);
        (uint256 x_kat0_res, uint256 y_kat0_res) = babyJubJub.toAffine(x_kat0, y_kat0, t_kat0, z_kat0);
        assertEq(x_kat0_res, 0);
        assertEq(y_kat0_res, 1);
        (uint256 x_kat1, uint256 y_kat1,, uint256 z_kat1) = babyJubJub.doubleTwistedEdwards(x_kat, y_kat, z_kat);

        (uint256 x_kat2, uint256 y_kat2,, uint256 z_kat2) = babyJubJub.doubleTwistedEdwards(x_kat1, y_kat1, z_kat1);
        (uint256 x_kat3, uint256 y_kat3, uint256 t_kat3, uint256 z_kat3) =
            babyJubJub.doubleTwistedEdwards(x_kat2, y_kat2, z_kat2);
        (uint256 x_kat3_res, uint256 y_kat3_res) = babyJubJub.toAffine(x_kat3, y_kat3, t_kat3, z_kat3);
        assertEq(x_kat3_res, 4304330865865803707709229766047793644695911410146585610031404541466966297585);
        assertEq(y_kat3_res, 13485835089156258613927479590259067246995570994808194133642502138584014679440);
    }

    function testScalarMul() public view {
        uint256 scalar0 = 0;
        uint256 point0_x = 0;
        uint256 point0_y = 1;

        uint256 scalar_kat = 1242440491034235814403315695115999933845748848737909651389506153219096971846;
        uint256 neg_one = 2736030358979909402780800718157159386076813972158567259200215660948447373040;
        uint256 point_kat_x = 5742303260101316936910431944725492393495696945462768307725717120096311286013;
        uint256 point_kat_y = 7586271879783443543166246816922473256134012536615268324850965019989201082300;

        (uint256 x_kat0, uint256 y_kat0) = babyJubJub.scalarMul(scalar0, point0_x, point0_y);
        (uint256 x_kat1, uint256 y_kat1) = babyJubJub.scalarMul(scalar_kat, point0_x, point0_y);
        (uint256 x_kat2, uint256 y_kat2) = babyJubJub.scalarMul(scalar0, point_kat_x, point_kat_y);
        (uint256 x_kat3, uint256 y_kat3) = babyJubJub.scalarMul(scalar_kat, point_kat_x, point_kat_y);
        (uint256 x_kat4, uint256 y_kat4) = babyJubJub.scalarMul(1, point_kat_x, point_kat_y);
        (uint256 x_kat5, uint256 y_kat5) = babyJubJub.scalarMul(2, point_kat_x, point_kat_y);
        (uint256 x_kat6, uint256 y_kat6) = babyJubJub.scalarMul(4, point_kat_x, point_kat_y);
        (uint256 x_kat7, uint256 y_kat7) = babyJubJub.scalarMul(42, point_kat_x, point_kat_y);
        (uint256 x_kat8, uint256 y_kat8) = babyJubJub.scalarMul(neg_one, point_kat_x, point_kat_y);
        assertEq(x_kat0, 0);
        assertEq(y_kat0, 1);
        assertEq(x_kat1, 0);
        assertEq(y_kat1, 1);
        assertEq(x_kat2, 0);
        assertEq(y_kat2, 1);
        assertEq(x_kat3, 20956092296700245265278265822140773756208216231379934457160271877025655741709);
        assertEq(y_kat3, 9373184734215645832232006489640453756569166652467933657649907245660614875035);
        assertEq(x_kat4, 5742303260101316936910431944725492393495696945462768307725717120096311286013);
        assertEq(y_kat4, 7586271879783443543166246816922473256134012536615268324850965019989201082300);
        assertEq(x_kat5, 6131772964403619322402663037312951525771688328127170096563629070357285349398);
        assertEq(y_kat5, 1836188316779156006438769797518498112508509464186868448746605336786159216920);
        assertEq(x_kat6, 8375249795494070168540398175218576938320513942163892031567097533429205888430);
        assertEq(y_kat6, 18441278903475799996286506656206445898730701347337446493298174331394670509347);
        assertEq(x_kat7, 1833532272404155580546508629437702206187237625211957633811621844821648822989);
        assertEq(y_kat7, 21395320191466327696365123237974277902424108876271626253976471516775696177004);
        assertEq(x_kat8, 16145939611737958285335973800531782695052667454953266035972487066479497209604);
        assertEq(y_kat8, 7586271879783443543166246816922473256134012536615268324850965019989201082300);
    }
}

