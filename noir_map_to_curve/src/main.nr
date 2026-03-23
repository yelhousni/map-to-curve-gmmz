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
