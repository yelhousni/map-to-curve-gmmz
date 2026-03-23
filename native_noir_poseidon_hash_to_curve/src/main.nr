// use dep::std::field::bn254;
// use dep::std::hash::poseidon;
// use dep::std::hash::blake2s;
// use dep::std::hash::blake3;
// use dep::std::hash::pedersen_hash;
use dep::std::collections::vec;
use dep::std::runtime::is_unconstrained;
use noir_custom_hashes::poseidon_hash_2;

global T: Field = 256;
// global i64_curve_b: i64 = -17;
// global CURVE_B: Field = i64_curve_b as Field;
global CURVE_B: Field = Field::from(0) - Field::from(17);
global MESSAGE_LEN_BYTES: u32 = 8;
global TWEAK_LEN_BYTES: u32 = 1;
// --------- The code below is the original code that we had for a native field --------- //

fn check_hash_constraints(m: Field, h: Field) -> bool {
    // let cond_1 = std::hash::poseidon::bn254::hash_2([m, 0]) == h;
    let cond_1 = poseidon_hash_2(m, 0) == h;
    // let cond_1 = std::hash::pedersen_hash([m, 0]) == h;

    cond_1
}

fn check_byte_hash_constraints(m: Field, h: [u8; 32]) -> bool {
    // let cond_1 = std::hash::blake2s([m as u8]) == h;
    let cond_1 = std::hash::blake3([m as u8]) == h;
    cond_1
}

// Number of MiMC rounds (for demonstration we use 8 rounds)
global MIMC_ROUNDS: u32 = 8;

// Round constants (example placeholders; TODO get standard constants!)
global MIMC_ROUND_CONSTANTS: [Field; MIMC_ROUNDS] = [
    Field::from(0),
    Field::from(1),
    Field::from(2),
    Field::from(3),
    Field::from(4),
    Field::from(5),
    Field::from(6),
    Field::from(7),
];

/// Computes the MiMC hash of two field elements.
///
/// # Arguments
/// - `left`: First input element
/// - `right`: Second input element
///
/// # Returns
/// - A single `Field` element representing the hash output.
fn get_mimc_hash(m: Field, t: Field) -> Field {
    // Initialize state by summing inputs
    let mut x = m + t;

    // Apply MiMC round function: x = (x + c_i)^5
    for i in 0..MIMC_ROUNDS {
        let c = MIMC_ROUND_CONSTANTS[i];
        x = (x + c).pow_32(5);
    }

    // Return the final state as the hash
    x
}

fn get_poseidon_hash(m: Field, t: Field) -> Field {
    // std::hash::poseidon::bn254::hash_2([m, t])
    poseidon_hash_2(m, t)
}

fn get_sha_hash(m: Field, t: Field) -> Field {
    let message_bytes: [u8; MESSAGE_LEN_BYTES] = m.to_le_bytes();
    let tweak_bytes: [u8; TWEAK_LEN_BYTES] = t.to_le_bytes();
    let mut input_bytes: [u8; MESSAGE_LEN_BYTES + TWEAK_LEN_BYTES] =
        [0; MESSAGE_LEN_BYTES + TWEAK_LEN_BYTES];
    for i in 0..MESSAGE_LEN_BYTES {
        input_bytes[i] = message_bytes[i];
    }
    for i in 0..TWEAK_LEN_BYTES {
        input_bytes[MESSAGE_LEN_BYTES + i] = tweak_bytes[i];
    }
    let hash_bytes =
        std::hash::sha256_var(input_bytes, (MESSAGE_LEN_BYTES + TWEAK_LEN_BYTES) as u64);
    Field::from_le_bytes(hash_bytes)
}

fn get_blake_hash(m: Field, t: Field) -> Field {
    let message_bytes: [u8; MESSAGE_LEN_BYTES] = m.to_le_bytes();
    let tweak_bytes: [u8; TWEAK_LEN_BYTES] = t.to_le_bytes();
    let mut input_bytes: [u8; MESSAGE_LEN_BYTES + TWEAK_LEN_BYTES] =
        [0; MESSAGE_LEN_BYTES + TWEAK_LEN_BYTES];
    for i in 0..MESSAGE_LEN_BYTES {
        input_bytes[i] = message_bytes[i];
    }
    for i in 0..TWEAK_LEN_BYTES {
        input_bytes[MESSAGE_LEN_BYTES + i] = tweak_bytes[i];
    }
    let hash_bytes = std::hash::blake3(input_bytes);
    Field::from_le_bytes(hash_bytes)
}

fn get_pedersen_hash(m: Field, t: Field) -> Field {
    std::hash::pedersen_hash([m, t])
}

fn check_hash_to_curve_constraints(m: Field, x: Field, y: Field, z: Field, t: Field) -> bool {
    let hash = get_poseidon_hash(m, t);
    // let hash = get_poseidon_hash(1, 1);
    // let hash = get_sha_hash(m, t);
    // let hash = get_blake_hash(m, t);
    // let hash = get_pedersen_hash(m, t);
    // let hash = get_mimc_hash(m, t);

    let cond_1 = (x == hash);
    let cond_2 = (y == (z * z));

    let x_sq = x * x;
    let f_x = (x_sq * x) + CURVE_B;

    let y_sq = y * y;

    let cond_3 = (y_sq == f_x);
    
    cond_1 * cond_2 * cond_3
}

// #[field(bn254)]
fn main(m: Field, x: Field, y: Field, z: Field, t: Field) {
    // assert(check_map_to_curve_constraints(m, x, y, z, t));
    assert(check_hash_to_curve_constraints(m, x, y, z, t));
    // assert(check_byte_hash_constraints(m, [0; 32]));

}

#[test]
fn test_main() {
    main(
        8,
        4187516063949292752547063834328607315615535772761064672064996989311068017434,
        19474072267714285322319129259200217646790759654585210420032195114162908003897,
        14533908148558754391837214299369098071743011723557408830591065550197762269424,
        6,
    );
}
