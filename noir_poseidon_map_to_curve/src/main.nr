// use dep::std::field::bn254;
// use dep::std::hash::poseidon;
// use dep::std::hash::blake2s;
// use dep::std::hash::blake3;
// use dep::std::hash::pedersen_hash;
use dep::std::runtime::is_unconstrained;
use noir_custom_hashes::poseidon_hash_2;
use non_native_field_ops::add_mod_p;
use non_native_field_ops::curve_B;
use non_native_field_ops::field_elt_to_native;
use non_native_field_ops::FieldElement256;
use non_native_field_ops::is_equal;
use non_native_field_ops::mul_mod_p;
use non_native_field_ops::NUM_CHUNKS;
global T: Field = 256;

fn check_poseidon_hash_to_curve_constraints(
    m: Field,
    nonce: Field,
    x: FieldElement256,
    y: FieldElement256,
    z: FieldElement256,
) -> bool {
    // Need to fix the type of hash, we'll need to break it into multiple 32 bits
    let hash = poseidon_hash_2(m, nonce);
    // print("Hash: \n");
    // print(hash);
    // print("\n");
    let x_native = field_elt_to_native(x);
    let cond_1 = (x_native == hash);
    let z_sq = mul_mod_p(z, z);
    let cond_2 = is_equal(y, z_sq);

    let x_sq = mul_mod_p(x, x);
    // let f_x = (x_sq * x) + 3;
    let f_x = add_mod_p(mul_mod_p(x_sq, x), curve_B());

    let y_sq = mul_mod_p(y, y);
    // print("Z square = ");
    // print(z*z);
    // print("\ny = ");
    // print(y);
    // print("\ny_sq = ");
    // print(y_sq);

    // print("\nf_x = ");
    // print(f_x);

    let cond_3 = is_equal(y_sq, f_x);
    // print("\n");
    // print(cond_1);
    // print("\n");
    // print(cond_2);
    // print("\n");
    // print(cond_3);
    // print("\n");

    // let zero: Field = Field::from(0);
    // let one: Field = Field::from(1);
    // let minus_one = (zero - one);
    // // print(minus_one);
    // let z_native = field_elt_to_native(z);
    // let y_native = field_elt_to_native(y);
    // let z_sq_native = z_native * z_native;
    // let cond_2_native = (z_sq_native == y_native);
    // let f_x_native = (x_native * x_native * x_native) - 17;
    // let y_sq_native = (y_native * y_native);
    // let cond_3_native = (y_sq_native == f_x_native);

    cond_1 * cond_2 * cond_3
}
// // #[field(bn254)]
fn main(m: Field, nonce: Field, x: FieldElement256, y: FieldElement256, z: FieldElement256) {
    let check = check_poseidon_hash_to_curve_constraints(m, nonce, x, y, z);
    assert(check);
}

// /// Elliptic-curve addition: R = point_p + point_q
// /// (using short Weierstrass formulas in affine coords).
// fn point_add(point_p: ECPoint, point_q: ECPoint) -> ECPoint {
//     // 1) Handle "point at infinity" shortcuts
//     if is_infinity(point_p) {
//         point_q
//     }
//     if is_infinity(point_q) {
//         point_p
//     }

//     // 2) If x_p == x_q but y_p != y_q => result = infinity
//     if is_equal(point_p.x, point_q.x) & !is_equal(point_p.y, point_q.y) {
//         ECPoint { x: zero_fe(), y: zero_fe() }
//     }

//     // 3) lambda = (y_q - y_p) / (x_q - x_p) mod p
//     let y_diff = sub_mod_p(point_q.y, point_p.y);
//     let x_diff = sub_mod_p(point_q.x, point_p.x);
//     let lambda = div_mod_p(y_diff, x_diff);

//     // 4) x_r = lambda^2 - x_p - x_q
//     let lambda_sq = mul_mod_p(lambda, lambda);
//     let t1 = sub_mod_p(lambda_sq, point_p.x);
//     let x_r = sub_mod_p(t1, point_q.x);

//     // 5) y_r = lambda * (x_p - x_r) - y_p
//     let x_p_minus_x_r = sub_mod_p(point_p.x, x_r);
//     let t2 = mul_mod_p(lambda, x_p_minus_x_r);
//     let y_r = sub_mod_p(t2, point_p.y);

//     ECPoint { x: x_r, y: y_r }
// }

// /// Elliptic-curve doubling: R = 2 * point_p
// fn point_double(point_p: ECPoint) -> ECPoint {
//     // 1) Handle infinity
//     if is_infinity(point_p) {
//         point_p
//     }

//     // 2) If y = 0 => vertical tangent => infinity
//     if is_equal(point_p.y, zero_fe()) {
//         ECPoint { x: zero_fe(), y: zero_fe() }
//     }

//     // 3) lambda = (3*x_p^2 + A) / (2*y_p)
//     let three = {
//         let mut fe = zero_fe();
//         fe.items[0] = Field::from(3);
//         fe
//     };
//     let two = {
//         let mut fe = zero_fe();
//         fe.items[0] = Field::from(2);
//         fe
//     };

//     let px_sq = mul_mod_p(point_p.x, point_p.x);         // x_p^2
//     let three_px_sq = mul_mod_p(three, px_sq);           // 3*x_p^2
//     let A = curve_A();                                   // A from your curve
//     let numerator = add_mod_p(three_px_sq, A);           // 3*x_p^2 + A

//     let two_py = mul_mod_p(two, point_p.y);              // 2*y_p
//     let lambda = div_mod_p(numerator, two_py);           // (3*x_p^2 + A)/(2*y_p)

//     // 4) x_r = lambda^2 - 2*x_p
//     let lambda_sq = mul_mod_p(lambda, lambda);
//     let two_px = mul_mod_p(two, point_p.x);
//     let x_r = sub_mod_p(lambda_sq, two_px);

//     // 5) y_r = lambda*(x_p - x_r) - y_p
//     let x_p_minus_x_r = sub_mod_p(point_p.x, x_r);
//     let t1 = mul_mod_p(lambda, x_p_minus_x_r);
//     let y_r = sub_mod_p(t1, point_p.y);

//     ECPoint { x: x_r, y: y_r }
// }

// /// Naive scalar multiplication using repeated add/double.
// /// For performance, you'd typically use double-and-add, but here is a simple version.
// fn point_scalar_mul(point_p: ECPoint, scalar: u64) -> ECPoint {
//     // We treat the "result" as infinity initially
//     let mut result = ECPoint { x: zero_fe(), y: zero_fe() };
//     let mut base = point_p;

//     // Example of doing a 64-bit naive loop. If you need 256-bit scalar exponents,
//     // you'd want to parse them into something bigger than u64 and loop more carefully.
//     for i in 0..64 {
//         let bit = (scalar >> i) & 1;
//         if bit == 1 {
//             result = point_add(result, base);
//         }
//         base = point_double(base);
//     }
//     result
// }

// --------- The code below is the original code that we had for a native field --------- //

// fn check_map_to_curve_constraints(m: Field, x: Field, y: Field, z: Field, t: Field) -> bool {
//     let cond_1 = (x == (t + m * T));
//     let cond_2 = (y == (z * z));

//     let x_sq = x * x;
//     // let f_x = (x_sq * x) + 3;
//     let f_x = (x_sq * x) - 17;

//     let y_sq = y * y;
//     print("Z square = ");
//     print(z*z);
//     print("\ny = ");
//     print(y);
//     print("\ny_sq = ");
//     print(y_sq);

//     print("\nf_x = ");
//     print(f_x);

//     let cond_3 = (y_sq == f_x);
//     print("\n");
//     print(cond_1);
//     print("\n");
//     print(cond_2);
//     print("\n");
//     print(cond_3);
//     print("\n");

//     let one: Field = 1;//Field::from(1);
//     let zero: Field = 0;//Field::from(0);
//     let minus_one = (zero - one);
//     print(minus_one);
//     cond_1 * cond_2 * cond_3

// }

// fn check_hash_constraints(m: Field, h: Field) -> bool {

//     let cond_1 = std::hash::poseidon::bn254::hash_2([m, 0]) == h;
//     // let cond_1 = std::hash::pedersen_hash([m, 0]) == h;

//     cond_1
// }

// fn check_byte_hash_constraints(m: Field, h: [u8; 32]) -> bool {

//     // let cond_1 = std::hash::blake2s([m as u8]) == h;
//     let cond_1 = std::hash::blake3([m as u8]) == h;
//     cond_1
// }

// // #[field(bn254)]
// fn main(m: Field, x: Field, y: Field, z: Field, t: Field) {
//     assert(check_map_to_curve_constraints(m, x, y, z, t));
//     // assert(check_hash_constraints(m, x));
//     // assert(check_byte_hash_constraints(m, [0; 32]));

// }

// #[test]
// fn test_main() {
//     main(7, 1792, 2222603532014808061213222263845635574143735707039159930479525957984581958699, 276759698173846535821495865193274967682377030871373817764620224677696820189, 0);
// }
