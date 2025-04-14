// use dep::std::field::bn254;
// use dep::std::hash::poseidon;
// use dep::std::hash::blake2s;
// use dep::std::hash::blake3;
// use dep::std::hash::pedersen_hash;
use dep::std::runtime::is_unconstrained;
global T: Field = 256;

global NON_NATIVE_T: FieldElement256 = FieldElement256 {
    items: [
        T, Field::from(0),
        Field::from(0), Field::from(0),
        Field::from(0), Field::from(0),
        Field::from(0), Field::from(0),
    ],
};


// ----- Here we deal with field representation and 
// arithmetic for a field that is larger than the native field ---- //
global NUM_CHUNKS = 8;
global CHUNK_SIZE = 32;
global CHUNK_SIZE_BYTES = CHUNK_SIZE / 8;
global NUM_BITS = 256;
global CHUNK_MOD = field_from_u64(1 << CHUNK_SIZE as u8);

global CARRY_BASE = field_from_u64(1 << CHUNK_SIZE as u8);
// BN254 Prime (Fr) in hex:
// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

struct FieldElement256 {    
    items: [Field; NUM_CHUNKS]
}









global ONE_P = FieldElement256 {
    items: [
        Field::from(1), Field::from(0),
        Field::from(0), Field::from(0),
        Field::from(0), Field::from(0),
        Field::from(0), Field::from(0),
    ],
};

// Converts a u64 value to an array of 8 u8 values (little-endian order)
unconstrained fn u64_to_le_bytes(x: u64) -> [u8; 8] {
    // Precomputed constants for powers of 256.
    let C0: u64 = 1;
    let C1: u64 = 256;
    let C2: u64 = 65536;            // 256^2
    let C3: u64 = 16777216;         // 256^3
    let C4: u64 = 4294967296;       // 256^4
    let C5: u64 = 1099511627776;    // 256^5
    let C6: u64 = 281474976710656;  // 256^6
    let C7: u64 = 72057594037927936; // 256^7

    let b0 = ((x / C0) % 256) as u8;
    let b1 = ((x / C1) % 256) as u8;
    let b2 = ((x / C2) % 256) as u8;
    let b3 = ((x / C3) % 256) as u8;
    let b4 = ((x / C4) % 256) as u8;
    let b5 = ((x / C5) % 256) as u8;
    let b6 = ((x / C6) % 256) as u8;
    let b7 = ((x / C7) % 256) as u8;
    [b0, b1, b2, b3, b4, b5, b6, b7]
}

// Uses the above function to create a Field element by converting the u64 to an array of 8 bytes 
// and then calling Field::from_le_bytes.
unconstrained fn field_from_u64(x: u64) -> Field {
    let bytes: [u8; 8] = u64_to_le_bytes(x);
    Field::from_le_bytes(bytes)
}





fn is_equal(a: FieldElement256, b: FieldElement256) -> bool {
    let mut equal = true;

    // Compare chunks starting from the most significant limb explicitly
    for j in 0..NUM_CHUNKS {
        let i = NUM_CHUNKS - 1 - j;
        equal = equal * (a.items[i].eq(b.items[i]));
    }
    equal
}




// // #[field(bn254)]
fn main(m: FieldElement256) {
    assert(is_equal(m, ONE_P));
}    


