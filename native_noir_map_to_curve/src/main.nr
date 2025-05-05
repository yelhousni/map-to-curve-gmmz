// use dep::std::field::bn254;
// use dep::std::hash::poseidon;
// use dep::std::hash::blake2s;
// use dep::std::hash::blake3;
// use dep::std::hash::pedersen_hash;
use dep::std::runtime::is_unconstrained;
global T: Field = 256;
global CURVE_B: Field = Field::from(0) - Field::from(17);

// --------- The code below is the original code that we had for a native field --------- //

fn check_map_to_curve_constraints(m: Field, x: Field, y: Field, z: Field, t: Field) -> bool {
    let cond_1 = (x == (t + m * T));
    let cond_2 = (y == (z * z));

    let x_sq = x * x;
    // let f_x = (x_sq * x) + 3;
    let f_x = (x_sq * x) + CURVE_B;

    let y_sq = y * y;
    

    let cond_3 = (y_sq == f_x);

    // let one: Field = 1; //Field::from(1);
    // let zero: Field = 0; //Field::from(0);
    // let minus_one = (zero - one);
    // print(minus_one);
    cond_1 * cond_2 * cond_3
}

fn check_hash_constraints(m: Field, h: Field) -> bool {
    let cond_1 = std::hash::poseidon::bn254::hash_2([m, 0]) == h;
    // let cond_1 = std::hash::pedersen_hash([m, 0]) == h;

    cond_1
}

fn check_byte_hash_constraints(m: Field, h: [u8; 32]) -> bool {
    // let cond_1 = std::hash::blake2s([m as u8]) == h;
    let cond_1 = std::hash::blake3([m as u8]) == h;
    cond_1
}

// #[field(bn254)]
fn main(m: Field, x: Field, y: Field, z: Field, t: Field) {
    assert(check_map_to_curve_constraints(m, x, y, z, t));
    // assert(check_hash_constraints(m, x));
    // assert(check_byte_hash_constraints(m, [0; 32]));

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
