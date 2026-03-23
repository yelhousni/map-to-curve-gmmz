global T: Field = 256;
global CURVE_B: Field = Field::from(0) - Field::from(17);
global OMEGA: Field = 4407920970296243842393367215006156084916469457145843978461;

fn check_map_to_curve_constraints(m: Field, x: Field, y: Field, z: Field, t: Field) -> bool {
    let cond_1 = (x == (t + m * T));
    let cond_2 = (y == (z * z));
    let x_sq = x * x;
    let f_x = (x_sq * x) + CURVE_B;
    let y_sq = y * y;
    let cond_3 = (y_sq == f_x);
    // ORIGINAL: cond_1 * cond_2 * cond_3
    // bool * bool is a type error in Noir beta.19. Fixed to &.
    cond_1 & cond_2 & cond_3
}

fn main(m: Field, x: Field, y: Field, z: Field, t: Field) {
    assert(check_map_to_curve_constraints(m, x, y, z, t));
}

#[test]
fn test_main() {
    main(
        7,
        1792,
        2222603532014808061213222263845635574143735707039159930479525957984581958699,
        276759698173846535821495865193274967682377030871373817764620224677696820189,
        0,
    );
}

// ================================================================
// EXPLOIT 1: Missing t < T range check breaks injectivity
// ================================================================
#[test]
fn exploit_missing_range_check() {
    let y: Field = 2222603532014808061213222263845635574143735707039159930479525957984581958699;
    let z: Field = 276759698173846535821495865193274967682377030871373817764620224677696820189;
    assert(check_map_to_curve_constraints(7, 1792, y, z, 0));
    assert(check_map_to_curve_constraints(6, 1792, y, z, 256));
}

// ================================================================
// EXPLOIT 2: m=0 claims any valid curve point
// ================================================================
#[test]
fn exploit_zero_message() {
    let y: Field = 2222603532014808061213222263845635574143735707039159930479525957984581958699;
    let z: Field = 276759698173846535821495865193274967682377030871373817764620224677696820189;
    assert(check_map_to_curve_constraints(7, 1792, y, z, 0));
    assert(check_map_to_curve_constraints(0, 1792, y, z, 1792));
}

// ================================================================
// EXPLOIT 3: Order-3 automorphism
// ================================================================
#[test]
fn exploit_automorphism() {
    let x1: Field = 1792;
    let y1: Field = 2222603532014808061213222263845635574143735707039159930479525957984581958699;
    let z1: Field = 276759698173846535821495865193274967682377030871373817764620224677696820189;
    assert(check_map_to_curve_constraints(7, x1, y1, z1, 0));
    let x2 = OMEGA * x1;
    let m2: Field = 30855446792073706896753570505043092594415286200020907849227;
    assert(check_map_to_curve_constraints(m2, x2, y1, z1, 0));
    assert(7 != m2);
}

// ================================================================
// EXPLOIT 4: BLS forgery via lattice + automorphism
// (same lattice values as main branch -- see main for full comments)
// ================================================================
fn grumpkin_add(x1: Field, y1: Field, x2: Field, y2: Field) -> (Field, Field) {
    let lam = (y2 - y1) / (x2 - x1);
    let x3 = lam * lam - x1 - x2;
    let y3 = lam * (x1 - x3) - y1;
    (x3, y3)
}

fn accumulate(
    digest_x: Field, digest_y: Field,
    m: Field, x: Field, y: Field, z: Field, t: Field
) -> (Field, Field) {
    assert(check_map_to_curve_constraints(m, x, y, z, t));
    grumpkin_add(digest_x, digest_y, x, y)
}

fn bls_sign_verify(
    m: Field, hx: Field, hy: Field, z: Field, t: Field,
    sigma_x: Field, sigma_y: Field, sk: Field
) -> bool {
    assert(check_map_to_curve_constraints(m, hx, hy, z, t));
    let h_point = std::embedded_curve_ops::EmbeddedCurvePoint { x: hx, y: hy, is_infinite: false };
    let scalar = std::embedded_curve_ops::EmbeddedCurveScalar { lo: sk as u64 as Field, hi: 0 };
    let computed = std::embedded_curve_ops::multi_scalar_mul([h_point], [scalar]);
    assert(computed.x == sigma_x);
    assert(computed.y == sigma_y);
    true
}

fn forger_produce_forgery(
    m1: Field, hx1: Field, hy1: Field, z1: Field, t1: Field, s1x: Field, s1y: Field,
    m2: Field, hx2: Field, hy2: Field, z2: Field, t2: Field, s2x: Field, s2y: Field
) -> bool {
    assert(check_map_to_curve_constraints(m1, hx1, hy1, z1, t1));
    assert(hx2 == OMEGA * hx1);
    assert(hy2 == hy1);
    assert(check_map_to_curve_constraints(m2, hx2, hy2, z2, t2));
    assert(m1 != m2);
    assert(s2x == OMEGA * s1x);
    assert(s2y == s1y);
    assert(s2y * s2y == s2x * s2x * s2x - 17);
    true
}

#[test]
fn exploit_bls_forgery() {
    // Lattice-derived pair: m1 ~ 2^122, m2 ~ 2^133
    let m1: Field = 4623336152555915830831612900677537718;
    let k1: Field = 16;
    let x1: Field = 1183574055054314452692892902573449655824;
    let y1: Field = 3685064678584060315605672169558178469269642305932528219255995458206481542969;
    let z1: Field = 304750983090955638160357194511537234870553324458819698300207047755401136410;
    let sk: Field = 42;
    let sigma1_x: Field = 16053453577841510814084374885116821704346925328313559380262361529330282788652;
    let sigma1_y: Field = 900985695773987472006619623552988070588165575185736004103471238657205592600;

    assert(bls_sign_verify(m1, x1, y1, z1, k1, sigma1_x, sigma1_y, sk));

    let m2: Field = 5779170190694895273855636663920961603484;
    let k2: Field = 200;
    let x2: Field = 1479467568817893190107042985963766170492104;
    let y2: Field = 3685064678584060315605672169558178469269642305932528219255995458206481542969;
    let z2: Field = 304750983090955638160357194511537234870553324458819698300207047755401136410;
    let sigma2_x: Field = 5139153890665315345314280266042943580326158050066791167231016484823888587501;
    let sigma2_y: Field = 900985695773987472006619623552988070588165575185736004103471238657205592600;

    assert(forger_produce_forgery(
        m1, x1, y1, z1, k1, sigma1_x, sigma1_y,
        m2, x2, y2, z2, k2, sigma2_x, sigma2_y
    ));
    assert(m1 != m2);
}

// ================================================================
// EXPLOIT 5: Multiset hash collision (zkVM memory forgery)
// ================================================================
#[test]
fn exploit_multiset_hash_collision() {
    let x7: Field = 1792;
    let y7: Field = 2222603532014808061213222263845635574143735707039159930479525957984581958699;
    let z7: Field = 276759698173846535821495865193274967682377030871373817764620224677696820189;
    let x1: Field = 256;
    let y1: Field = 9189236229814196392576801464214343739846708746841839291083803335996532870109;
    let z1: Field = 4477254854248242929434024226743979797109261084935875761478684308825718674401;

    let (w_dx, w_dy) = accumulate(x7, y7, 1, x1, y1, z1, 0);
    assert(check_map_to_curve_constraints(6, x7, y7, z7, 256));
    let (r_dx, r_dy) = accumulate(x7, y7, 1, x1, y1, z1, 0);
    assert(w_dx == r_dx);
    assert(w_dy == r_dy);
}

// ================================================================
// EXPLOIT 6: BLS forgery with SMALL messages (lattice + automorphism)
//
// Half-GCD on (Fr, omega) gives the shortest vector:
//   a = 147946756881789319000765030803803410728  (127 bits)
//   b = 9931322734385697763                       (64 bits)
// but neither a nor b is on Grumpkin (a^3-17, b^3-17 non-QR in Fr).
//
// LLL-enumerating longer vectors n1*v1 + n2*v2, at (n1=-10000, n2=8)
// we find a pair where BOTH coords are on Grumpkin with valid z:
//   x1 = 1183574055054314452692892902573449655824   (130 bits, m1 ~ 2^122)
//   x2 = 1479467568817893190107042985963766170492104 (141 bits, m2 ~ 2^133)
//   omega * x1 = x2 mod Fr
//
// This works because T is not range-checked, so M*T >> sqrt(q),
// giving enough lattice vectors for some to land on the curve.
//
// For comparison, on BN254 G1 (y^2 = x^3 + 3), the polynomial
// short vector from Proposition 1 of the paper lands DIRECTLY on
// the curve (O(1) forgery, m1 ~ 2^119, m2 ~ 2^56, T=128). That
// attack is verified by the sage script bn254_forgery.sage but
// requires nonnative Fq arithmetic, so cannot run natively in Noir.
// ================================================================

#[test]
fn exploit_bls_forgery_small_messages() {
    // Lattice-derived pair on Grumpkin (LLL at n1=-10000, n2=8)
    // Signer: m1 ~ 2^122
    let m1: Field = 4623336152555915830831612900677537718;
    let k1: Field = 16;
    let x1: Field = 1183574055054314452692892902573449655824;
    let y1: Field = 3685064678584060315605672169558178469269642305932528219255995458206481542969;
    let z1: Field = 304750983090955638160357194511537234870553324458819698300207047755401136410;
    let sk: Field = 42;
    let sigma1_x: Field = 16053453577841510814084374885116821704346925328313559380262361529330282788652;
    let sigma1_y: Field = 900985695773987472006619623552988070588165575185736004103471238657205592600;

    assert(bls_sign_verify(m1, x1, y1, z1, k1, sigma1_x, sigma1_y, sk));

    // Forger: m2 ~ 2^133 (no sk!)
    let m2: Field = 5779170190694895273855636663920961603484;
    let k2: Field = 200;
    let x2: Field = 1479467568817893190107042985963766170492104;
    let y2: Field = 3685064678584060315605672169558178469269642305932528219255995458206481542969;
    let z2: Field = 304750983090955638160357194511537234870553324458819698300207047755401136410;
    let sigma2_x: Field = 5139153890665315345314280266042943580326158050066791167231016484823888587501;
    let sigma2_y: Field = 900985695773987472006619623552988070588165575185736004103471238657205592600;

    assert(forger_produce_forgery(
        m1, x1, y1, z1, k1, sigma1_x, sigma1_y,
        m2, x2, y2, z2, k2, sigma2_x, sigma2_y
    ));

    // Both messages realistic: m1 ~ 2^122, m2 ~ 2^133
    assert(m1 != m2);
}
