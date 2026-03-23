use non_native_field_ops::{
    add_mod_p, curve_B, field_elt_to_native, is_equal,
    mul_mod_p, T,
};
use non_native_field_ops::FieldElement256;

fn fe256(c0: Field, c1: Field, c2: Field, c3: Field,
         c4: Field, c5: Field, c6: Field, c7: Field) -> FieldElement256 {
    FieldElement256 { items: [c0, c1, c2, c3, c4, c5, c6, c7] }
}

pub fn check_nonnative_map_to_curve_constraints(
    m: Field,
    x: FieldElement256,
    y: FieldElement256,
    z: FieldElement256,
    t: Field,
) -> bool {
    let m_times_t = m * T;
    let t_plus_m_times_t = t + m_times_t;
    let x_native = field_elt_to_native(x);
    let cond_1 = (x_native == t_plus_m_times_t);
    let z_sq = mul_mod_p(z, z);
    let cond_2 = is_equal(y, z_sq);
    let x_sq = mul_mod_p(x, x);
    let f_x = add_mod_p(mul_mod_p(x_sq, x), curve_B());
    let y_sq = mul_mod_p(y, y);
    let cond_3 = is_equal(y_sq, f_x);
    // ORIGINAL: cond_1 * cond_2 * cond_3. Fixed to &.
    cond_1 & cond_2 & cond_3
}

fn main(m: Field, x: FieldElement256, y: FieldElement256, z: FieldElement256, nonce: Field) {
    assert(check_nonnative_map_to_curve_constraints(m, x, y, z, nonce));
}

// ================================================================
// Honest baseline
// ================================================================
#[test]
fn test_honest_m7_t0() {
    let x = fe256(1792, 0, 0, 0, 0, 0, 0, 0);
    let y = fe256(572898347, 1394700396, 437080213, 4012180472,
                  3757856850, 1410540546, 3929418899, 82440946);
    let z = fe256(1662833629, 1544638068, 1841881003, 3246470374,
                  3394126905, 79692451, 3209578632, 10265587);
    main(7, x, y, z, 0);
}

// ================================================================
// EXPLOIT 1: Missing t < T (cond_1 uses native Field)
// ================================================================
#[test]
fn exploit_missing_range_check_nonnative() {
    let x = fe256(1792, 0, 0, 0, 0, 0, 0, 0);
    let y = fe256(572898347, 1394700396, 437080213, 4012180472,
                  3757856850, 1410540546, 3929418899, 82440946);
    let z = fe256(1662833629, 1544638068, 1841881003, 3246470374,
                  3394126905, 79692451, 3209578632, 10265587);
    // Honest: m=7, t=0
    assert(check_nonnative_map_to_curve_constraints(7, x, y, z, 0));
    // Malicious: m=6, t=256 -> same x=1792
    assert(check_nonnative_map_to_curve_constraints(6, x, y, z, 256));
}

// ================================================================
// EXPLOIT 2: Automorphism with nonnative FieldElement256
// x2 = omega * 1792, decomposed as FieldElement256 limbs
// ================================================================
#[test]
fn exploit_automorphism_nonnative() {
    let x1 = fe256(1792, 0, 0, 0, 0, 0, 0, 0);
    let y1 = fe256(572898347, 1394700396, 437080213, 4012180472,
                   3757856850, 1410540546, 3929418899, 82440946);
    let z1 = fe256(1662833629, 1544638068, 1841881003, 3246470374,
                   3394126905, 79692451, 3209578632, 10265587);
    assert(check_nonnative_map_to_curve_constraints(7, x1, y1, z1, 0));

    // x2 = omega * 1792 mod q, 32-bit limbs (little-endian)
    let x2 = fe256(1207307008, 2808663827, 3752498381, 3855039454,
                   2678286979, 1642417355, 1258, 0);
    let m2: Field = 30855446792073706896753570505043092594415286200020907849227;
    assert(check_nonnative_map_to_curve_constraints(m2, x2, y1, z1, 0));
    assert(7 != m2);
}

// ================================================================
// EXPLOIT 3: mul_mod_p non-canonical reduction
// basic_reduce hint returns (q, r) with no constraint r < p.
// Non-canonical r causes is_equal to reject valid witnesses.
// ================================================================
#[test]
fn exploit_mul_mod_p_noncanonical() {
    let z1 = fe256(1662833629, 1544638068, 1841881003, 3246470374,
                   3394126905, 79692451, 3209578632, 10265587);
    let y1 = fe256(572898347, 1394700396, 437080213, 4012180472,
                   3757856850, 1410540546, 3929418899, 82440946);
    let z_sq = mul_mod_p(z1, z1);
    assert(is_equal(z_sq, y1));

    // Non-canonical: add p[0] to first limb
    let y1_noncanon = fe256(
        572898347 + 4026531841,
        1394700396, 437080213, 4012180472,
        3757856850, 1410540546, 3929418899, 82440946
    );
    // Chunk representations differ -> is_equal returns false
    assert(!is_equal(y1_noncanon, y1));
}

// ================================================================
// EXPLOIT 4: Multiset hash collision (zkVM memory forgery)
// ================================================================

fn grumpkin_add_native(x1: Field, y1: Field, x2: Field, y2: Field) -> (Field, Field) {
    let lam = (y2 - y1) / (x2 - x1);
    let x3 = lam * lam - x1 - x2;
    let y3 = lam * (x1 - x3) - y1;
    (x3, y3)
}

fn accumulate_nonnative(
    digest_x: Field, digest_y: Field,
    m: Field, x: FieldElement256, y: FieldElement256, z: FieldElement256, t: Field
) -> (Field, Field) {
    assert(check_nonnative_map_to_curve_constraints(m, x, y, z, t));
    let x_nat = field_elt_to_native(x);
    let y_nat = field_elt_to_native(y);
    grumpkin_add_native(digest_x, digest_y, x_nat, y_nat)
}

#[test]
fn exploit_multiset_hash_collision_nonnative() {
    let x7 = fe256(1792, 0, 0, 0, 0, 0, 0, 0);
    let y7 = fe256(572898347, 1394700396, 437080213, 4012180472,
                   3757856850, 1410540546, 3929418899, 82440946);
    let z7 = fe256(1662833629, 1544638068, 1841881003, 3246470374,
                   3394126905, 79692451, 3209578632, 10265587);

    let x1 = fe256(256, 0, 0, 0, 0, 0, 0, 0);
    let y1 = fe256(3370929117, 2877315975, 1546370264, 1117512247,
                   2593641976, 3768686594, 1878898216, 340847715);
    let z1 = fe256(1392006113, 3532185325, 520250368, 504186490,
                   1400030876, 3061485160, 1871433087, 166070612);

    // Write log: [m=7, m=1]
    let (w_dx, w_dy) = accumulate_nonnative(
        1792,
        2222603532014808061213222263845635574143735707039159930479525957984581958699,
        1, x1, y1, z1, 0
    );

    // Forger proves m=6 maps to pt(7) using t=256
    assert(check_nonnative_map_to_curve_constraints(6, x7, y7, z7, 256));

    // Read log: [m=6 (forged!), m=1] -- same digest as write
    let (r_dx, r_dy) = accumulate_nonnative(
        1792,
        2222603532014808061213222263845635574143735707039159930479525957984581958699,
        1, x1, y1, z1, 0
    );

    assert(w_dx == r_dx);
    assert(w_dy == r_dy);
}

// ================================================================
// EXPLOIT 5: BLS signature forgery via lattice + automorphism
//
// Lattice-derived pair (from half-GCD on (Fr, omega), LLL enumeration):
//   x1 = 1183574055054314452692892902573449655824   (130 bits, m1 ~ 2^122)
//   x2 = 1479467568817893190107042985963766170492104 (141 bits, m2 ~ 2^133)
//   omega * x1 = x2 mod Fr
//   Both on Grumpkin with valid z witnesses.
// ================================================================

fn bls_sign_verify_nonnative(
    m: Field, hx: FieldElement256, hy: FieldElement256, z: FieldElement256, t: Field,
    sigma_x: Field, sigma_y: Field, sk: Field
) -> bool {
    assert(check_nonnative_map_to_curve_constraints(m, hx, hy, z, t));
    let hx_nat = field_elt_to_native(hx);
    let hy_nat = field_elt_to_native(hy);
    let h_point = std::embedded_curve_ops::EmbeddedCurvePoint { x: hx_nat, y: hy_nat, is_infinite: false };
    let scalar = std::embedded_curve_ops::EmbeddedCurveScalar { lo: sk as u64 as Field, hi: 0 };
    let computed = std::embedded_curve_ops::multi_scalar_mul([h_point], [scalar]);
    assert(computed.x == sigma_x);
    assert(computed.y == sigma_y);
    true
}

global OMEGA_NATIVE: Field = 4407920970296243842393367215006156084916469457145843978461;

fn forger_produce_forgery_nonnative(
    m1: Field, hx1: FieldElement256, hy1: FieldElement256, z1: FieldElement256, t1: Field,
    s1x: Field, s1y: Field,
    m2: Field, hx2: FieldElement256, hy2: FieldElement256, z2: FieldElement256, t2: Field,
    s2x: Field, s2y: Field
) -> bool {
    assert(check_nonnative_map_to_curve_constraints(m1, hx1, hy1, z1, t1));
    let hx1_nat = field_elt_to_native(hx1);
    let hx2_nat = field_elt_to_native(hx2);
    assert(hx2_nat == OMEGA_NATIVE * hx1_nat);
    assert(check_nonnative_map_to_curve_constraints(m2, hx2, hy2, z2, t2));
    assert(m1 != m2);
    assert(s2x == OMEGA_NATIVE * s1x);
    assert(s2y == s1y);
    assert(s2y * s2y == s2x * s2x * s2x - 17);
    true
}

#[test]
fn exploit_bls_forgery_nonnative() {
    // Signer: m1 ~ 2^122
    let m1: Field = 4623336152555915830831612900677537718;
    let k1: Field = 16;
    let x1 = fe256(2622469648, 1219009062, 1975696092, 2053902919, 3, 0, 0, 0);
    let y1 = fe256(294678329, 2822596739, 3209066498, 3434817956,
                   3163712164, 2002080, 3070255743, 136686645);
    let z1 = fe256(1957300506, 2298056835, 2731082278, 476827814,
                   2318180287, 2598581859, 898035184, 11303842);
    let sk: Field = 42;

    let sigma1_x: Field = 16053453577841510814084374885116821704346925328313559380262361529330282788652;
    let sigma1_y: Field = 900985695773987472006619623552988070588165575185736004103471238657205592600;

    assert(bls_sign_verify_nonnative(m1, x1, y1, z1, k1, sigma1_x, sigma1_y, sk));

    // Forger: m2 ~ 2^133 (no sk!)
    let m2: Field = 5779170190694895273855636663920961603484;
    let k2: Field = 200;
    let x2 = fe256(3578240200, 3946516296, 20655268, 3283173613, 4347, 0, 0, 0);
    let y2 = fe256(294678329, 2822596739, 3209066498, 3434817956,
                   3163712164, 2002080, 3070255743, 136686645);
    let z2 = fe256(1957300506, 2298056835, 2731082278, 476827814,
                   2318180287, 2598581859, 898035184, 11303842);

    let sigma2_x: Field = 5139153890665315345314280266042943580326158050066791167231016484823888587501;
    let sigma2_y: Field = 900985695773987472006619623552988070588165575185736004103471238657205592600;

    assert(forger_produce_forgery_nonnative(
        m1, x1, y1, z1, k1, sigma1_x, sigma1_y,
        m2, x2, y2, z2, k2, sigma2_x, sigma2_y
    ));
    assert(m1 != m2);
}
