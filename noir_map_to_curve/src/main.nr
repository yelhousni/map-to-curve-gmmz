global T: Field = 256;

fn check_map_to_curve_constraints(m: Field, x: Field, y: Field, z: Field, t: Field) -> bool {
    let cond_1 = (x == (t + m * T));
    let cond_2 = (y == (z * z));
    
    let x_sq = x * x;
    // let f_x = (x_sq * x) + 3;
    let f_x = (x_sq * x) - 17;
    
    let y_sq = y * y;
    print("Z square = ");
    print(z*z);
    print("\ny = ");
    print(y);
    print("\ny_sq = ");
    print(y_sq);

    print("\nf_x = ");
    print(f_x);

    let cond_3 = (y_sq == f_x);
    print("\n");
    print(cond_1);
    print("\n");
    print(cond_2);
    print("\n");
    print(cond_3);
    print("\n");


    let minus_one = Field::from(0) - Field::from(1);
    print(minus_one);
    cond_1 & cond_2 & cond_3
    
}



// #[field(bn254)]
fn main(m: Field, x: Field, y: Field, z: Field, t: Field) {
    assert(check_map_to_curve_constraints(m, x, y, z, t));

}

#[test]
fn test_main() {
    main(7, 1792, 2222603532014808061213222263845635574143735707039159930479525957984581958699, 276759698173846535821495865193274967682377030871373817764620224677696820189, 0);
}

// ================================================================
// EXPLOIT: Missing t < T range check breaks injectivity
//
// The circuit does NOT enforce t < T (= 256). The constraint is only:
//   x == t + m * T
// A malicious prover can choose any t, including t >= T, and pick m
// accordingly so that a DIFFERENT message maps to the SAME x (and
// therefore the same curve point).
//
// Honest:    m=7,  t=0   -> x = 0 + 7*256   = 1792
// Malicious: m=6,  t=256 -> x = 256 + 6*256  = 1792  (same point!)
//
// Both pass the circuit. Two distinct messages share one group element.
// This breaks multiset hash injectivity and BLS unforgeability.
// ================================================================

#[test]
fn exploit_missing_range_check() {
    let y: Field = 2222603532014808061213222263845635574143735707039159930479525957984581958699;
    let z: Field = 276759698173846535821495865193274967682377030871373817764620224677696820189;

    // Honest: m=7, t=0 -> x = 1792
    assert(check_map_to_curve_constraints(7, 1792, y, z, 0));

    // Malicious: m=6, t=256 (t >= T) -> x = 256 + 6*256 = 1792
    assert(check_map_to_curve_constraints(6, 1792, y, z, 256));

    // Both accepted. Messages 7 and 6 map to the same Grumpkin point.
}

// ================================================================
// EXPLOIT: Order-3 automorphism on Grumpkin (j=0 curve)
//
// Grumpkin has equation y^2 = x^3 - 17 (a=0, j-invariant 0).
// The map phi(x,y) = (omega*x, y) is an order-3 automorphism:
//   (omega*x)^3 - 17 = omega^3 * x^3 - 17 = x^3 - 17 = y^2
// so phi(P) is on the curve whenever P is.
//
// omega = 4407920970296243842393367215006156084916469457145843978461
//       = 3^((q-1)/3) mod q,  where q = BN254 Fr
//
// Starting from the honest witness m1=7, x1=1792:
//   x2 = omega * 1792 mod q
//   m2 = x2 // 256 = 30855446792073706896753570505043092594415286200020907849227
//   t2 = x2 %  256 = 0
//
// The forged witness (m2, x2, y1, z1, t2=0) passes ALL constraints.
// No out-of-range t is needed. This is a purely algebraic attack.
// Cost: 1 field multiplication on public data.
// ================================================================

global OMEGA: Field = 4407920970296243842393367215006156084916469457145843978461;

#[test]
fn exploit_automorphism() {
    let x1: Field = 1792;
    let y1: Field = 2222603532014808061213222263845635574143735707039159930479525957984581958699;
    let z1: Field = 276759698173846535821495865193274967682377030871373817764620224677696820189;

    // Honest witness
    assert(check_map_to_curve_constraints(7, x1, y1, z1, 0));

    // Automorphism: x2 = omega * x1, y2 = y1, z2 = z1
    let x2 = OMEGA * x1;
    let m2: Field = 30855446792073706896753570505043092594415286200020907849227;
    let t2: Field = 0;  // in-range!

    // Forged witness passes -- different message, valid t
    assert(check_map_to_curve_constraints(m2, x2, y1, z1, t2));

    // Messages are different
    assert(7 != m2);
}

// ================================================================
// EXPLOIT: m=0 claims ANY valid curve point
//
// With m=0 the constraint becomes x == t + 0*256 = t.
// Since t is unbounded, the attacker sets t = x for ANY valid x.
// This means message m=0 can claim ownership of every curve point
// in every message range -- a universal collision.
// ================================================================

#[test]
fn exploit_zero_message_claims_any_point() {
    let y: Field = 2222603532014808061213222263845635574143735707039159930479525957984581958699;
    let z: Field = 276759698173846535821495865193274967682377030871373817764620224677696820189;

    // Honest: m=7, t=0 -> x = 1792
    assert(check_map_to_curve_constraints(7, 1792, y, z, 0));

    // Forger: m=0, t=1792 -> x = 1792 + 0*256 = 1792
    assert(check_map_to_curve_constraints(0, 1792, y, z, 1792));

    // m=0 stole m=7's curve point
    assert(0 != 7);
}

// ================================================================
// Grumpkin affine addition
// ================================================================
fn grumpkin_add(x1: Field, y1: Field, x2: Field, y2: Field) -> (Field, Field) {
    let lam = (y2 - y1) / (x2 - x1);
    let x3 = lam * lam - x1 - x2;
    let y3 = lam * (x1 - x3) - y1;
    (x3, y3)
}

// Accumulate: verify map-to-curve then add to running digest
fn accumulate(
    digest_x: Field, digest_y: Field,
    m: Field, x: Field, y: Field, z: Field, t: Field
) -> (Field, Field) {
    assert(check_map_to_curve_constraints(m, x, y, z, t));
    grumpkin_add(digest_x, digest_y, x, y)
}

// ================================================================
// EXPLOIT: Multiset hash collision -- zkVM memory forgery
//
// A zkVM checks memory consistency via multiset hashing:
//   write_digest = sum of MapToCurve(addr) for each write
//   read_digest  = sum of MapToCurve(addr) for each read
//   assert(write_digest == read_digest)
//
// The missing t < T check lets a malicious prover map m=6 to the
// SAME group element as m=7 (using t=256). So the prover can
// substitute address 6 for address 7 in the read log, and the
// multiset digests still match.
//
// Write log: [m=7, m=1]  -- program writes to addresses 7 and 1
// Read log:  [m=6, m=1]  -- attacker claims reads from 6 and 1
//
// The attacker proves m=6 maps to pt(7) using t=256.
// Both digests are pt(7) + pt(1) -- they match.
// Memory safety is violated: the read was for address 6, not 7.
// ================================================================

#[test]
fn exploit_multiset_hash_collision() {
    let x7: Field = 1792;
    let y7: Field = 2222603532014808061213222263845635574143735707039159930479525957984581958699;
    let z7: Field = 276759698173846535821495865193274967682377030871373817764620224677696820189;

    let x1: Field = 256;
    let y1: Field = 9189236229814196392576801464214343739846708746841839291083803335996532870109;
    let z1: Field = 4477254854248242929434024226743979797109261084935875761478684308825718674401;

    // --- HONEST WRITE LOG: [m=7, m=1] ---
    let (w_dx, w_dy) = accumulate(x7, y7, 1, x1, y1, z1, 0);

    // --- FORGED READ LOG: [m=6, m=1] ---
    // Attacker uses t=256 to make m=6 map to the same point as m=7
    // So the first element of the read log is pt(7), same as the write log
    assert(check_map_to_curve_constraints(6, x7, y7, z7, 256));
    let (r_dx, r_dy) = accumulate(x7, y7, 1, x1, y1, z1, 0);

    // Digests match -- zkVM accepts the forged memory
    assert(w_dx == r_dx);
    assert(w_dy == r_dy);

    // But the read was for address 6, not 7
    assert(6 != 7);
}

// ================================================================
// EXPLOIT: BLS signature forgery via order-3 automorphism
//
// This implements the attack from Section 5.2 of El Housni & Bunz (2025),
// adapted from the SageMath script bn254_forgery.sage.
//
// ---- Lattice approach (Section 5.2 of El Housni & Bunz 2025) ----
//
// The automorphism phi(x,y) = (omega*x, y) induces the lattice
//   L = {(a,b) in Z^2 : b = omega*a mod q}
// of determinant q. By Minkowski's theorem, L has a non-zero vector
// with max(|a|,|b|) <= sqrt(q). The half-GCD on (q, omega) finds:
//   a = 147946756881789319000765030803803410728  (127 bits)
//   b = 9931322734385697763                       (64 bits)
// but NEITHER is on Grumpkin (a^3-17 and b^3-17 are non-QR in Fr).
//
// By LLL-enumerating longer lattice vectors (n1*v1 + n2*v2) we find
// a valid pair at (n1=-10000, n2=8) with both coords on Grumpkin:
//   x1 = 1183574055054314452692892902573449655824   (130 bits)
//   x2 = 1479467568817893190107042985963766170492104 (141 bits)
//   omega * x1 = x2 mod q  (positive, no sign flip)
//   Both x1^3-17 and x2^3-17 are QR, and y1 = y2 (since x1^3 = x2^3).
//   Both y values have valid sqrt (z witness exists).
//
// Messages: m1 ~ 2^122, m2 ~ 2^133 -- both realistic.
// This is a concrete BLS forgery with small messages on Grumpkin.
//
// BLS signing:
//   sk       = secret key (private)
//   P1       = MapToCurve(m1)
//   sigma1   = [sk] * P1          (signature on m1)
//
// The forger sees only public data: P1, sigma1, omega.
// The forger computes (WITHOUT sk):
//   P2       = phi(P1)     = (omega * P1.x, P1.y)
//   sigma2   = phi(sigma1) = (omega * sigma1.x, sigma1.y)
//
// Correctness: phi commutes with scalar multiplication:
//   sigma2 = phi([sk]*P1) = [sk]*phi(P1) = [sk]*P2
//
// The BLS verifier checks e(sigma2, g2) = e(P2, vk) -- passes.
// Cost: 2 field multiplications on public data. No sk needed.
// ================================================================

fn bls_sign_verify(
    m: Field, hx: Field, hy: Field, z: Field, t: Field,
    sigma_x: Field, sigma_y: Field,
    sk: Field  // PRIVATE -- unknown to forger
) -> bool {
    assert(check_map_to_curve_constraints(m, hx, hy, z, t));
    let h_point = std::embedded_curve_ops::EmbeddedCurvePoint {
        x: hx, y: hy, is_infinite: false
    };
    let scalar = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: sk as u64 as Field, hi: 0
    };
    let computed = std::embedded_curve_ops::multi_scalar_mul([h_point], [scalar]);
    assert(computed.x == sigma_x);
    assert(computed.y == sigma_y);
    true
}

fn forger_produce_forgery(
    // signed message (public)
    m1: Field, hx1: Field, hy1: Field, z1: Field, t1: Field,
    s1x: Field, s1y: Field,
    // forged message (public) -- NO sk
    m2: Field, hx2: Field, hy2: Field, z2: Field, t2: Field,
    s2x: Field, s2y: Field
) -> bool {
    // (a) P1 is a valid encoding of m1
    assert(check_map_to_curve_constraints(m1, hx1, hy1, z1, t1));

    // (b) P2 = phi(P1)
    assert(hx2 == OMEGA * hx1);
    assert(hy2 == hy1);

    // (c) P2 is a valid encoding of m2
    assert(check_map_to_curve_constraints(m2, hx2, hy2, z2, t2));
    assert(m1 != m2);

    // (d) sigma2 = phi(sigma1)
    assert(s2x == OMEGA * s1x);
    assert(s2y == s1y);

    // (e) sigma2 is on Grumpkin
    assert(s2y * s2y == s2x * s2x * s2x - 17);

    true
}

#[test]
fn exploit_bls_forgery() {
    // --- STEP 1: honest signer signs m1 with sk=42 ---
    // m1 ~ 2^122 (realistic message from lattice short vector)
    let m1: Field = 4623336152555915830831612900677537718;
    let x1: Field = 1183574055054314452692892902573449655824;
    let y1: Field = 3685064678584060315605672169558178469269642305932528219255995458206481542969;
    let z1: Field = 304750983090955638160357194511537234870553324458819698300207047755401136410;
    let k1: Field = 16;
    let sk: Field = 42;

    let sigma1_x: Field = 16053453577841510814084374885116821704346925328313559380262361529330282788652;
    let sigma1_y: Field = 900985695773987472006619623552988070588165575185736004103471238657205592600;

    // Signer's proof (sk is private witness)
    assert(bls_sign_verify(m1, x1, y1, z1, k1, sigma1_x, sigma1_y, sk));

    // --- STEP 2: forger applies phi to public data (no sk!) ---
    // m2 ~ 2^133 (also realistic -- from the same lattice vector)
    let m2: Field = 5779170190694895273855636663920961603484;
    let x2: Field = 1479467568817893190107042985963766170492104;
    let y2: Field = 3685064678584060315605672169558178469269642305932528219255995458206481542969;
    let z2: Field = 304750983090955638160357194511537234870553324458819698300207047755401136410;
    let k2: Field = 200;

    let sigma2_x: Field = 5139153890665315345314280266042943580326158050066791167231016484823888587501;
    let sigma2_y: Field = 900985695773987472006619623552988070588165575185736004103471238657205592600;

    // Forger's proof -- no sk in the argument list
    assert(forger_produce_forgery(
        m1, x1, y1, z1, k1, sigma1_x, sigma1_y,
        m2, x2, y2, z2, k2, sigma2_x, sigma2_y
    ));

    // Forgery: valid signature on m2 != m1, produced without sk
    // Both messages are small (~122 and ~133 bits) -- realistic
    assert(m1 != m2);
}
