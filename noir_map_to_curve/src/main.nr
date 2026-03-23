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
