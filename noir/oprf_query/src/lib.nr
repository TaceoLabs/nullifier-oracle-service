use babyjubjub::{BabyJubJubPoint, BabyJubJubScalar};
use eddsa_babyjubjub_poseidon2::{EdDSAPublicKey, EdDSASignature};
use poseidon2::bn254::perm::{x5_16, x5_2, x5_4};

fn merkle_leaf(x: [BabyJubJubPoint; 7]) -> Field {
    x5_16([
        105702839725298824521994315, // Domain Separator
        x[0].x(),
        x[0].y(),
        x[1].x(),
        x[1].y(),
        x[2].x(),
        x[2].y(),
        x[3].x(),
        x[3].y(),
        x[4].x(),
        x[4].y(),
        x[5].x(),
        x[5].y(),
        x[6].x(),
        x[6].y(),
        0,
    ])[1] // return the second element as the hash output, capacity is at 0
}

fn poseidon2_compression_mode(input: [Field; 2]) -> Field {
    x5_2(input)[0] + input[0]
}

fn compute_binary_merkle_root<let MAX_DEPTH: u32>(
    leaf: Field,
    index: Field,
    siblings: [Field; MAX_DEPTH],
    depth: u32,
) -> Field {
    assert(index.lt(2.pow_32(depth as Field)));
    let index_bits: [u1; MAX_DEPTH] = index.to_le_bits();
    binary_merkle_root::binary_merkle_root(
        poseidon2_compression_mode,
        leaf,
        depth,
        index_bits,
        siblings,
    )
}

fn choose_public_key(index: Field, public_keys: [BabyJubJubPoint; 7]) -> BabyJubJubPoint {
    // index is in [0, 6]
    let cmp = [index == 0, index == 1, index == 2, index == 3, index == 4, index == 5, index == 6];
    let mut dot_x = public_keys[0].x() * cmp[0] as Field;
    let mut dot_y = public_keys[0].y() * cmp[0] as Field;
    for i in 1..7 {
        dot_x += public_keys[i].x() * cmp[i] as Field;
        dot_y += public_keys[i].y() * cmp[i] as Field;
    }

    // Resulting public key is not checked to be non-zero here, it is checked in the EdDSA verifier later on. Both checks (BabyJubJubCheck and is_zero() on the x coordinate) in EdDSAPoseidon2Verifier() trigger a failure in case the output is zero.
    BabyJubJubPoint::new_unchecked(dot_x, dot_y)
}

fn check_credential_signature(
    sig: EdDSASignature,
    pk: EdDSAPublicKey,
    credential_type_id: Field,
    user_id: Field,
    genesis_issued_at: u64,
    expires_at: u64,
    current_timestamp: u64,
    hashes: [Field; 2],
) {
    assert(current_timestamp < expires_at); // Check that the credential is not expired
    let message = poseidon2::bn254::perm::x5_8([
        33037561950257263916064606852876458089761913554974635334680016433, // Domain Separator
        credential_type_id,
        user_id,
        genesis_issued_at as Field,
        expires_at as Field,
        hashes[0],
        hashes[1],
        0,
    ])[1]; // return the second element as the hash output, capacity is at 0

    assert(pk.verify(sig, message)); // Verify the signature
}

pub fn oprf_query<let MAX_DEPTH: u32>(
    // signature verification of the oprf nonce
    pks: [[Field; 2]; 7],
    pk_index: Field,
    s: Field,
    r: [Field; 2],
    // credential signature parts
    cred_type_id: Field, // public
    cred_pk: [Field; 2],
    cred_hashes: [Field; 2],
    cred_genesis_issued_at: u64,
    cred_expires_at: u64,
    cred_s: Field,
    cred_r: [Field; 2],
    current_timestamp: u64, //public
    // Merkle tree parts
    merkle_root: Field,
    depth: u32, //public
    mt_index: Field,
    siblings: [Field; MAX_DEPTH],
    // oprf query
    beta: Field,
    rp_id: Field, // public
    action: Field, // public
    nonce: Field,
) -> [Field; 2] {
    let query = x5_4(
        [1773399373884719043551600379785849, mt_index, rp_id, action],
    )[1];
    // range check beta to be < Subgroup order
    let beta_fr = BabyJubJubScalar::new(beta);

    // 1. Verify sk/pk by verifying a signature to a known message
    // we chose one of the PKs based on pk_index, we do not at this point check they are valid points
    let pk_points = [
        BabyJubJubPoint::new_unchecked(pks[0][0], pks[0][1]),
        BabyJubJubPoint::new_unchecked(pks[1][0], pks[1][1]),
        BabyJubJubPoint::new_unchecked(pks[2][0], pks[2][1]),
        BabyJubJubPoint::new_unchecked(pks[3][0], pks[3][1]),
        BabyJubJubPoint::new_unchecked(pks[4][0], pks[4][1]),
        BabyJubJubPoint::new_unchecked(pks[5][0], pks[5][1]),
        BabyJubJubPoint::new_unchecked(pks[6][0], pks[6][1]),
    ];
    let chosen_pk = choose_public_key(pk_index, pk_points);
    // once we have chosen the PK, we check it is valid
    let public_key = EdDSAPublicKey::from_parts(chosen_pk.x(), chosen_pk.y());
    // check that the signature is valid
    let signature = EdDSASignature::from_parts(r[0], r[1], s);
    // verify the signature
    assert(public_key.verify(signature, query));

    // 2. Merkle proof of pk
    // Hash the pk to get a field element, which is the leaf
    let merkle_leaf = merkle_leaf(pk_points);

    let computed_root = compute_binary_merkle_root(merkle_leaf, mt_index, siblings, depth);
    assert(computed_root == merkle_root); // Check that the computed root matches the provided root

    // 3. Query is computed correctly
    let oprf_point = encode_to_curve::encode_to_curve_babyjubjub(query);
    let blinded_point = oprf_point.mul(beta_fr);

    // 4. Credential signature is valid
    let cred_sig = EdDSASignature::from_parts(cred_r[0], cred_r[1], cred_s);
    let cred_pk = EdDSAPublicKey::from_parts(cred_pk[0], cred_pk[1]);
    check_credential_signature(
        cred_sig,
        cred_pk,
        cred_type_id,
        mt_index,
        cred_genesis_issued_at,
        cred_expires_at,
        current_timestamp,
        cred_hashes,
    );
    // Dummy square to prevent tampering nonce.
    // Same as done in Semaphore
    // TODO: does this do anything in Noir?
    let _nonce_squared = nonce * nonce;

    [blinded_point.x(), blinded_point.y()]
}

mod tests {
    use super::oprf_query;

    #[test]
    fn test_oprf_query() {
        let pk: [[Field; 2]; 7] = [
            [
                12926335063978273448089741990924527827340544719094547009383816569581332416077,
                13601884821482902342518099314271713773927626584774316227795436923954815979717,
            ],
            [
                17450117902723239913277610979414100673447132837920489702213807876612747509643,
                16137008596637751386179454566413586733682162455789939096403985283452780455164,
            ],
            [
                16237843485360606587948110136866452104450238956897325525580364972442323282231,
                3038199591545151035096046129187054767485743573812817709607657634776566820033,
            ],
            [
                17191566428545261714452004623071303139696553222638026287816371855646740145905,
                93070624739026369871981807504394783485945227376954894449406808936424643950,
            ],
            [
                15941546582704556566009683779200328340768038766577446590429470381128345714224,
                6815816660179804382991025529751543224116895366190337208853189682550659201573,
            ],
            [
                20600691266336331279034026612799520212438838834101681366245799348198930584061,
                2929014319892711941993425292447088381458360932720775139607412714549140755507,
            ],
            [
                21205212545400683746417587413459096336124716248684161693010042948678074657273,
                13514902520888721899095605594384356845757660861027099037056854100930738545107,
            ],
        ];
        let pk_index = 0;
        let s = 2364413558049615625319842141782619041889285871538502856649701262922425213004;
        let r = [
            6175612728637629485087191228020330116606602022719282638712380102842504854908,
            17437243393862770527889891370658737731377038475147560198044797003868574678179,
        ];
        let cred_type_id =
            3414707727665405215413872560007166747682162426669267667947566666945224874361;
        let cred_pk = [
            3911939777713244726036470610724914218301380017737886149469021643561666735476,
            7797629098545048698495189705475406627806430965193809733158656266154222463350,
        ];
        let cred_hashes = [
            13977834369929188974757768747349799868191471529117526579503803036696137904793,
            6313794860217247756634274584520282195123758390973784975719163237885969588988,
        ];
        let cred_genesis_issued_at = 1785158915210294107;
        let cred_expires_at = 4155967309548383240;
        let cred_s = 1780690930310289378915338565504462637839648711264641836741423338318195078335;
        let cred_r = [
            4053928218991411219715757732459205792542179676359226209806599555981120218957,
            16464089594192569269304696136577195835829781727534533754463681827521912387848,
        ];
        let current_time_stamp = 2649580743198312473;
        let merkle_root =
            21814879738315839607612810901470394522159443117785754878388531030240687945121;
        let depth = 10;
        let mt_index = 619;
        let siblings = [
            585667135721753969363509939300211011246556245223812717046690099385593273174,
            13831276848914456433029944485688452931943276765267741191127219913539274952909,
            15123163260382119529154699958310842429671386656986509951998058885724184625211,
            3698702788246529553998844916267818368435299657182417440867583687256534559455,
            15009307841198748046734354117872496801061930613634362932433916018409464931320,
            17755219582132495894705533450858798905341479365658436522558995884914908206475,
            4510870697710898789031470398971957650637843318989665041899201573351849687225,
            13728601500714660164204724228361781808217876930452909341427924627120091660145,
            367163834445130469708330074562703722303807574404567970933209548626671695554,
            10749291063558121804414082224321566190292085012775435926940002682854965857323,
        ];
        let beta = 1140356135826306566819741125920391259145283870741121629642574110498733923956;
        let rp_id = 14543781253279221655341348046093482030359842858497268799758461103786468968520;
        let action = 11645641403676661130561889787211885818940845317622158566969546584908643962625;
        let nonce = 2236132571319938347910518696643047589185681298608183023074417259533825907089;

        let result = oprf_query::<10>(
            pk,
            pk_index,
            s,
            r,
            cred_type_id,
            cred_pk,
            cred_hashes,
            cred_genesis_issued_at,
            cred_expires_at,
            cred_s,
            cred_r,
            current_time_stamp,
            merkle_root,
            depth,
            mt_index,
            siblings,
            beta,
            rp_id,
            action,
            nonce,
        );
        assert(
            result
                == [
                    19835723778083871419514662517727270835340903087582795899030891051326373360547,
                    2294171513652264915547750236737808874693400457197058622699756260222886603019,
                ],
        )
    }
}
