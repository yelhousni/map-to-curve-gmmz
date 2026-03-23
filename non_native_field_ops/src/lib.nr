pub global T: Field = 256;

global NON_NATIVE_T: FieldElement256 = FieldElement256 {
    items: [
        T,
        Field::from(0),
        Field::from(0),
        Field::from(0),
        Field::from(0),
        Field::from(0),
        Field::from(0),
        Field::from(0),
    ],
};

// ----- Here we deal with field representation and
// arithmetic for a field that is larger than the native field ---- //
global NUM_CHUNKS: u32 = 8;
global CHUNK_SIZE: u32 = 32;
global CHUNK_SIZE_BYTES: u32 = CHUNK_SIZE / 8;
global NUM_BITS: u32 = 256;
global CHUNK_MOD: Field = field_from_u64(1u64 << (CHUNK_SIZE as u64));

global CARRY_BASE: Field = field_from_u64(1u64 << (CHUNK_SIZE as u64));
global M: u32 = NUM_CHUNKS / 2;
global M2: u32 = M + 1; // 5

// BN254 Prime (Fr) in hex:
// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

pub struct FieldElement256 {
    pub items: [Field; NUM_CHUNKS],
}

pub struct FieldElement512 {
    items: [Field; 2 * NUM_CHUNKS],
}

pub struct FieldElement512Partial {
    items: [Field; NUM_CHUNKS + 1],
}

pub fn field_elt_to_native(elt: FieldElement256) -> Field {
    let mut res = Field::from(0);
    let mut factor = Field::from(1);
    for i in 0..NUM_CHUNKS {
        res = res + (elt.items[i] * factor);
        factor = factor * CHUNK_MOD;
    }
    res
}

fn u32_arr_to_field_const(arr: [[u8; CHUNK_SIZE_BYTES]; NUM_CHUNKS]) -> FieldElement256 {
    let mut res = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    for i in 0..NUM_CHUNKS {
        res.items[i] = Field::from_le_bytes::<4>(arr[i]);
    }
    res
}

// Returns the 0 element in your custom 256-bit field
fn zero_fe() -> FieldElement256 {
    FieldElement256 { items: [Field::from(0); NUM_CHUNKS] }
}

fn u32_arr_to_field_const257(
    arr: [[u8; CHUNK_SIZE_BYTES]; NUM_CHUNKS + 1],
) -> FieldElement512Partial {
    let mut res = FieldElement512Partial { items: [Field::from(0); NUM_CHUNKS + 1] };
    for i in 0..NUM_CHUNKS + 1 {
        res.items[i] = Field::from_le_bytes::<4>(arr[i]);
    }
    res
}

pub fn field256_to_512(elt: FieldElement256) -> FieldElement512 {
    let mut res = FieldElement512 { items: [Field::from(0); 2 * NUM_CHUNKS] };
    for i in 0..NUM_CHUNKS {
        res.items[i] = elt.items[i];
    }
    res
}

fn field512_to_256(elt: FieldElement512) -> FieldElement256 {
    let mut res = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    for i in 0..NUM_CHUNKS {
        res.items[i] = elt.items[i];
    }
    res
}

// global p_le_bytes: [[u8; 4]; 8] = [
//     [71, 253, 124, 216],
//     [22, 140, 32, 60],
//     [141, 202, 113, 104],
//     [145, 106, 129, 151],
//     [93, 88, 129, 129],
//     [182, 69, 80, 184],
//     [41, 160, 49, 225],
//     [114, 78, 100, 48],
// ];
global p_le_bytes: [[u8; 4]; 8] = [
    [1, 0, 0, 240], 
    [147, 245, 225, 67], 
    [145, 112, 185, 121], 
    [72, 232, 51, 40], 
    [93, 88, 129, 129], 
    [182, 69, 80, 184], 
    [41, 160, 49, 225], 
    [114, 78, 100, 48]];

global mu_le_bytes: [[u8; 4]; 9] = [
    [201, 67, 45, 153],
    [215, 183, 165, 83],
    [215, 247, 27, 76],
    [157, 106, 250, 229],
    [192, 202, 198, 24],
    [242, 104, 23, 178],
    [160, 250, 255, 199],
    [73, 149, 241, 48],
    [3, 0, 0, 0],
];

// Note that we need to use 32-bit chunks for the field elements,
// when using a "64-bit" native field, such as Goldilocks,
// since the underlying field is usually less than 64 bits in reality,
// and working with 64-bit chunks could cause overflow.


global p: FieldElement256 = u32_arr_to_field_const(p_le_bytes);

global p_512: FieldElement512 = field256_to_512(p);

global MU: FieldElement512Partial = u32_arr_to_field_const257(mu_le_bytes);

global P_MINUS_2: FieldElement256 = FieldElement256 {
    items: [
        Field::from(0xd87cfd45),
        Field::from(0x3c208c16),
        Field::from(0x6871ca8d),
        Field::from(0x97816a91),
        Field::from(0x8181585d),
        Field::from(0xb85045b6),
        Field::from(0xe131a029),
        Field::from(0x30644e72),
    ],
};

global ONE_P: FieldElement256 = FieldElement256 {
    items: [
        Field::from(1),
        Field::from(0),
        Field::from(0),
        Field::from(0),
        Field::from(0),
        Field::from(0),
        Field::from(0),
        Field::from(0),
    ],
};

// Converts a u64 value to an array of 8 u8 values (little-endian order)
unconstrained fn u64_to_le_bytes(x: u64) -> [u8; 8] {
    // Precomputed constants for powers of 256.
    let C0: u64 = 1;
    let C1: u64 = 256;
    let C2: u64 = 65536; // 256^2
    let C3: u64 = 16777216; // 256^3
    let C4: u64 = 4294967296; // 256^4
    let C5: u64 = 1099511627776; // 256^5
    let C6: u64 = 281474976710656; // 256^6
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

unconstrained fn field_to_u128(x: Field) -> u128 {
    x as u128
}

unconstrained fn field_from_u128(x: u128) -> Field {
    x as Field
}

unconstrained fn split_u128(x: u128) -> (u128, u128) {
    let chunk_mod_128: u128 = 1u128 << 32u128;
    let lo = x % chunk_mod_128;
    let hi = x / chunk_mod_128;
    (lo, hi)
}

unconstrained fn shift_right_u128(x: u128, s: u64) -> u128 {
    let num_shifts: u64 = s / 8;
    let rem: u8 = (s % 8) as u8;
    let mut result: u128 = x;
    for i in 0..16 {
        if i < num_shifts {
            result = result >> 8u128;
        }
    }
    result = result >> (rem as u128);
    result
}

unconstrained fn shift_left_u128(x: u128, s: u64) -> u128 {
    let num_shifts: u64 = s / 8;
    let rem: u8 = (s % 8) as u8;
    let mut result: u128 = x;
    let u128_256: u128 = 256;
    for i in 0..16 {
        if i < num_shifts {
            result = result * u128_256;
        }
    }
    result = result << (rem as u128);
    result
}

fn is_greater_or_equal(a: FieldElement256, b: FieldElement256) -> bool {
    let mut result = false;
    let mut equal = true;
    for j in 0..NUM_CHUNKS {
        let i = NUM_CHUNKS - 1 - j;
        result = result | (equal & b.items[i].lt(a.items[i]));
        equal = equal & a.items[i].eq(b.items[i]);
    }
    result | equal
}

fn is_greater_than(a: FieldElement256, b: FieldElement256) -> bool {
    let mut result = false;
    let mut equal = true;
    for j in 0..NUM_CHUNKS {
        let i = NUM_CHUNKS - 1 - j;
        result = result | (equal & b.items[i].lt(a.items[i]));
        equal = equal & a.items[i].eq(b.items[i]);
    }
    result
}

pub fn is_equal(a: FieldElement256, b: FieldElement256) -> bool {
    let mut equal = true;

    // Compare chunks starting from the most significant chunk explicitly
    for j in 0..NUM_CHUNKS {
        let i = NUM_CHUNKS - 1 - j;
        equal = equal & a.items[i].eq(b.items[i]);
    }
    equal
}

fn is_greater_than_512(a: FieldElement512, b: FieldElement512) -> bool {
    let mut result = false;
    let mut equal = true;

    // Start from most significant chunk and descend to least significant chunk
    for j in 0..(2 * NUM_CHUNKS) {
        let i = (2 * NUM_CHUNKS - 1 - j);

        let a_lt_b = a.items[i].lt(b.items[i]); // a < b at chunk i
        let b_lt_a = b.items[i].lt(a.items[i]); // b < a at chunk i implies a > b at chunk i

        // Update result ONLY if chunks were equal so far and now we find a > b.
        result = result | (equal & b_lt_a);

        // Update "equal" status for next chunk.
        equal = equal & !(a_lt_b | b_lt_a);
    }

    result
}

fn is_greater_than_eq_512(a: FieldElement512, b: FieldElement512) -> bool {
    let mut result = false;
    let mut equal = true;

    for j in 0..(2 * NUM_CHUNKS) {
        // Go lower from most significant chunk
        let i = (2 * NUM_CHUNKS - 1 - j);

        let a_lt_b = a.items[i].lt(b.items[i]);
        let b_lt_a = b.items[i].lt(a.items[i]);

        result = result | (equal & b_lt_a);

        equal = equal & !(a_lt_b | b_lt_a);
    }

    result | equal // result or equal (since >= includes equality)
}

fn is_equal_512(a: FieldElement512, b: FieldElement512) -> bool {
    let mut equal = true;

    // Compare chunks starting from the most significant chunk explicitly
    for j in 0..2 * NUM_CHUNKS {
        let i = 2 * NUM_CHUNKS - 1 - j;
        equal = equal & a.items[i].eq(b.items[i]);
    }
    equal
}

// Add two CHUNK_SIZE-bit integers with an incoming carry bit
// Input:
//   a, b: Field elements to be added
//   carry_in: incoming carry bit (0 or 1)
// Output:
//   (sum: Field, carry_out: Field)
fn add_with_carry(a: Field, b: Field, carry_in: Field) -> (Field, Field) {
    // Intermediate sum (128-bit intermediate to detect overflow)
    let sum_ab = a + b + carry_in;
    let carry_out = if !sum_ab.lt(CARRY_BASE) {
        Field::from(1)
    } else {
        Field::from(0)
    };
    let chunk = sum_ab - carry_out * CARRY_BASE;
    (chunk, carry_out)
}

fn add_256(a: FieldElement256, b: FieldElement256) -> (FieldElement256, Field) {
    // Add two 256-bit integers
    // Input:
    //   a, b: Field elements to be added
    // Output:
    //   (sum: FieldElement256, carry_out: Field)

    let mut sum = FieldElement256 { items: [0; NUM_CHUNKS] };
    let mut carry_out = 0;

    for i in 0..NUM_CHUNKS {
        let (sum_i, carry): (Field, Field) = add_with_carry(a.items[i], b.items[i], carry_out);
        sum.items[i] = sum_i;
        carry_out = carry;
    }
    // Ensure that there is no overflow in the final carry
    // This is a 256-bit addition, so the carry_out should be 0
    assert(carry_out == 0);
    (sum, carry_out)
}

fn add_512(a: FieldElement512, b: FieldElement512) -> (FieldElement512, Field) {
    // Add two 512-bit integers
    // Input:
    //   a, b: Field elements to be added
    // Output:
    //   (sum: FieldElement512, carry_out: Field)

    let mut sum = FieldElement512 { items: [0; 2 * NUM_CHUNKS] };
    let mut carry_out = 0;

    for i in 0..2 * NUM_CHUNKS {
        let (sum_i, carry): (Field, Field) = add_with_carry(a.items[i], b.items[i], carry_out);
        sum.items[i] = sum_i;
        carry_out = carry;
    }
    // Ensure that there is no overflow in the final carry
    // This is a 512-bit addition, so the carry_out should be 0
    assert(carry_out == 0);
    (sum, carry_out)
}

// // Inputs: a, b are in the Field  borrow_in is in {0,1}
// // Outputs: (chunk, borrow_out)
// fn sub_with_borrow_field_chunk_size(a: Field, b: Field, borrow_in: Field) -> (Field, Field) {
//     // // let borrow_base = CARRY_BASE;
//     // let b_plus_borrow = b + borrow_in;

//     // let borrow_out = if a.lt(b_plus_borrow) { Field::from(1) } else { Field::from(0) };

//     // let chunk = a - b_plus_borrow + borrow_out * CARRY_BASE;

//     // // // Correctness constraints for sanity (Noir-friendly)
//     // // // assert(chunk + borrow_out * borrow_base == a - b - borrow_in);
//     // // // assert((borrow_out == Field::from(0)) + (borrow_out == Field::from(1)) == 1);

//     // (chunk, borrow_out)
//     // 1) form the thing we really want to compare against:
//     let bpb = b + borrow_in;

//     // 2) borrow if and only if a < b + borrow_in
//     //    Noir-style branch --> 1 when true, 0 when false
//     let borrow_out = if a.lt(bpb) {
//         Field::from(1)
//     } else {
//         Field::from(0)
//     };

//     // 3) chunk = a - (b+borrow_in) + borrow_out * CARRY_BASE
//     //    (this brings us back into [0, CARRY_BASE) if we did borrow)
//     let chunk = a - bpb + borrow_out * CARRY_BASE;

//     (chunk, borrow_out)

// }

fn sub_with_borrow_field_chunk_size(a: Field, b: Field, borrow_in: Field) -> (Field, Field) {
    let bpb = b + borrow_in;
    let borrow_out = if a.lt(bpb) {
        Field::from(1)
    } else {
        Field::from(0)
    };
    let chunk = a - bpb + borrow_out * CARRY_BASE;
    (chunk, borrow_out)
}

// Subtract two 256-bit integers

fn sub_field256(a: FieldElement256, b: FieldElement256) -> (FieldElement256, Field) {
    let mut res = [Field::from(0); NUM_CHUNKS];
    let mut borrow = Field::from(0);

    for i in 0..NUM_CHUNKS {
        let out = sub_with_borrow_field_chunk_size(a.items[i], b.items[i], borrow);
        res[i] = out.0;
        borrow = out.1;
    }
    // At the end, borrow indicates if we underflowed the entire 256-bit number.
    // borrow = 0: a greater than eq to b
    // borrow = 1: a < b
    let res_field = FieldElement256 { items: res };
    (res_field, borrow)
}

fn sub_field512(a: FieldElement512, b: FieldElement512) -> (FieldElement512, Field) {
    let mut res = [Field::from(0); 2 * NUM_CHUNKS];
    let mut borrow = Field::from(0);

    for i in 0..2 * NUM_CHUNKS {
        let out = sub_with_borrow_field_chunk_size(a.items[i], b.items[i], borrow);
        res[i] = out.0;
        borrow = out.1;
    }
    // At the end, borrow indicates if we underflowed the entire 512-bit number.
    // borrow = 0: a greater than eq to b
    // borrow = 1: a < b
    let res_field = FieldElement512 { items: res };
    (res_field, borrow)
}

pub fn add_mod_p(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
    let mut res = [Field::from(0); NUM_CHUNKS];
    let mut carry = Field::from(0);

    // Step 1: Explicit chunk-wise addition with carry

    for i in 0..NUM_CHUNKS {
        let (sum_i, carry): (Field, Field) = add_with_carry(a.items[i], b.items[i], carry);
        res[i] = sum_i;
    }

    // // Now, explicitly, carry might be 0 or 1
    let res_field = FieldElement256 { items: res };

    // Step 2: Explicitly subtract modulus `p` to check if res greater than eq to p or if carry occurred
    let out = sub_field256(res_field, p);
    let res_minus_p = out.0;
    let borrow = out.1;

    // Step 3: Decide explicitly:
    // If carry == 1 (overflow), res is definitely greater than eq to p
    // OR if borrow == 0 (res greater than eq to p), then reduce explicitly by p.
    // Else, keep original res explicitly.
    // let reduce_flag = (Field::from(1) - borrow) + carry;
    let reduce_flag = if is_greater_or_equal(res_field, p) {
        1
    } else {
        0
    };
    // reduce_flag greater than eq to 1 if carry==1 or no borrow (res greater than eq to p)

    // Convert reduce_flag explicitly to a boolean (0 or 1)

    assert((reduce_flag * (reduce_flag - 1)).eq(Field::from(0)));

    let mut final_res = [Field::from(0); NUM_CHUNKS];
    for i in 0..NUM_CHUNKS {
        final_res[i] = res_minus_p.items[i] * reduce_flag + res[i] * (Field::from(1) - reduce_flag);
    }
    FieldElement256 { items: final_res }
}

fn sub_mod_p(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
    let mut res = [Field::from(0); NUM_CHUNKS];
    let mut borrow = Field::from(0);

    for i in 0..NUM_CHUNKS {
        let out = sub_with_borrow_field_chunk_size(a.items[i], b.items[i], borrow);
        res[i] = out.0;
        borrow = out.1;
    }
    // If negative, add p back
    let mut carry = Field::from(0);
    for i in 0..NUM_CHUNKS {
        let out = add_with_carry(res[i], p.items[i] * borrow, carry);
        res[i] = out.0;
        carry = out.1;
    }
    FieldElement256 { items: res }
}
// Negation of a 256-bit integer

// Multiply two 256-bit integers

fn mul_field32(a: Field, b: Field) -> (Field, Field) {
    let product: Field = a * b;
    let prod_u128: u128 = unsafe { field_to_u128(product) };

    // Use the unconstrained split function.
    let (lo_u128, hi_u128) = unsafe { split_u128(prod_u128) };

    let lo: Field = unsafe { field_from_u128(lo_u128) };
    let hi: Field = unsafe { field_from_u128(hi_u128) };

    assert(hi * CHUNK_MOD + lo == product);

    (lo, hi)
}

fn mul_chunks_8x8_schoolbook(a: FieldElement256, b: FieldElement256) -> FieldElement512 {
    let mut out = FieldElement512 { items: [Field::from(0); 2 * NUM_CHUNKS] };

    // Outer loops: multiply each chunk from a and b.
    for i in 0..NUM_CHUNKS {
        for j in 0..NUM_CHUNKS {
            // Multiply a chunk from a and b (32x32 = 64 bits).
            let (lo, hi) = mul_field32(a.items[i], b.items[j]);

            // Add the product into the appropriate positions in out.
            let (sum_lo, carry1) = add_with_carry(out.items[i + j], lo, Field::from(0));
            let (sum_hi, carry2) = add_with_carry(out.items[i + j + 1], hi, carry1);

            out.items[i + j] = sum_lo;
            out.items[i + j + 1] = sum_hi;

            // Now propagate any carry.
            let mut carry = carry2;
            // Fixed loop: run for exactly 2 * NUM_CHUNKS iterations.
            // for offset in 0..(2 * NUM_CHUNKS) {
            //     // Calculate the target index.
            //     let k = i + j + 2 + offset;
            //     // Only perform an update if k is in range.
            //     if k < 2 * NUM_CHUNKS {
            //         let (sum, new_carry) = add_with_carry(out.items[k], Field::from(0), carry);
            //         out.items[k] = sum;
            //         carry = new_carry;
            //     }
            // }
            let start = i + j + 2;
            // if start < 2 * NUM_CHUNKS {
            for k in start..(2 * NUM_CHUNKS) {
                let (sum, new_carry) = add_with_carry(out.items[k], Field::from(0), carry);
                out.items[k] = sum;
                carry = new_carry;
            }
            // }
        }
    }

    out
}

fn mul_chunks_8x8_deferred(a: FieldElement256, b: FieldElement256) -> FieldElement512 {
    let zero = Field::from(0);

    // 1) Schoolbook accumulate ALL partial products into a big 16-limb accumulator
    let mut out = FieldElement512 { items: [zero; 2 * NUM_CHUNKS] };
    for i in 0..NUM_CHUNKS {
        let ai = a.items[i];
        for j in 0..NUM_CHUNKS {
            let bj = b.items[j];
            let (lo, hi) = mul_field32(ai, bj);
            let idx = i + j;
            out.items[idx] += lo;
            out.items[idx + 1] += hi;
        }
    }

    // // 2) One single carry-propagate over all 16 limbs
    // let mut carry = zero;
    // for k in 0..2 * NUM_CHUNKS {
    //     let (s, c) = add_with_carry(out.items[k], zero, carry);
    //     out.items[k] = s;
    //     carry = c;
    // }

    // out
    // 2) single-pass ``full'' normalize
    //    carry_out = sum / 2^32,  chunk = sum - carry_out*2^32
    let mut carry = zero;
    for k in 0..2 * NUM_CHUNKS {
        let sum = out.items[k] + carry;
        // integer division in the field, safe because sum < p
        // let carry_out = sum.div_floor(carry_base);
        let (carry_out, chunk) = unsafe { arithmetic_div_chunk_size(sum) };
        assert(chunk.lt(CARRY_BASE)); // ensures chunk in [0,2^32)
        assert(sum == carry_out * CARRY_BASE + chunk);
        let chunk = sum - carry_out * CARRY_BASE; // chunk = sum - carry_out*2^32
        out.items[k] = chunk;
        carry = carry_out;
    }

    out
}

// (A) Split a 8-chunk element into two 4-chunk halves
fn split4(a: FieldElement256) -> (FieldElement256, FieldElement256) {
    let mut lo = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut hi = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    // NUM_CHUNKS == 8, so half = 4
    for i in 0..NUM_CHUNKS / 2 {
        lo.items[i] = a.items[i];
        hi.items[i] = a.items[i + NUM_CHUNKS / 2];
        // if i < NUM_CHUNKS / 2 {
        // lo.items[i] = a.items[i];
        // } else {
        // hi.items[i - NUM_CHUNKS / 2] = a.items[i];
        // }
    }
    (lo, hi)
}

// (B) 4x4 schoolbook multiply --> 8-chunk result in a 16-slot FieldElement512.
//     Just shrink your existing mul_chunks_8x8 to 4 --> 8.
fn mul_chunks_4x4(a: FieldElement256, b: FieldElement256) -> FieldElement512 {
    let mut out = FieldElement512 { items: [Field::from(0); 2 * NUM_CHUNKS] };
    let zero = Field::from(0);

    for i in 0..M {
        let ai = a.items[i];
        for j in 0..M {
            let bj = b.items[j];
            let (lo, hi) = mul_field32(ai, bj);
            let idx = i + j;

            // add lo, hi with carry
            let (s0, c0) = add_with_carry(out.items[idx], lo, zero);
            let (s1, mut carry) = add_with_carry(out.items[idx + 1], hi, c0);
            out.items[idx] = s0;
            out.items[idx + 1] = s1;

            // propagate carry up to NUM_CHUNKS-1
            for k in (idx + 2)..NUM_CHUNKS {
                let (s, c2) = add_with_carry(out.items[k], zero, carry);
                out.items[k] = s;
                carry = c2;
            }
        }
    }
    out
}

fn mul_chunks_4x4_deferred(a: FieldElement256, b: FieldElement256) -> FieldElement512 {
    let mut out = FieldElement512 { items: [Field::from(0); 2 * NUM_CHUNKS] };

    // 1) Accumulate all partial products without carrying
    for i in 0..M {
        let ai = a.items[i];
        for j in 0..M {
            let bj = b.items[j];
            let (lo, hi) = mul_field32(ai, bj);
            let idx = i + j;
            out.items[idx] = out.items[idx] + lo;
            out.items[idx + 1] = out.items[idx + 1] + hi;
        }
    }

    // 2) One final O(OUT) carry-propagate to reduce each limb into [0, CARRY_BASE)
    let mut carry = Field::from(0);
    for k in 0..NUM_CHUNKS {
        let (s, c) = add_with_carry(out.items[k], Field::from(0), carry);
        out.items[k] = s;
        carry = c;
    }

    out
}

// fn mul_chunks_5x5_deferred(a: FieldElement256, b: FieldElement256) -> FieldElement512 {
//     let mut out = FieldElement512 { items: [Field::from(0); 2*NUM_CHUNKS] };
//     // 1) accumulate all M2xM2 products
//     for i in 0..M2 {
//         let ai = a.items[i];
//         for j in 0..M2 {
//             let bj = b.items[j];
//             let (lo, hi) = mul_field32(ai, bj);
//             let idx = i + j;
//             out.items[idx]     += lo;
//             out.items[idx + 1] += hi;
//         }
//     }
//     // 2) normalize *every* one of the 16 limbs, so no carry is dropped
//     let mut carry = Field::from(0);
//     for k in 0..2*NUM_CHUNKS {
//         // let x = if k < OUT2 { out.items[k] } else { Field::from(0) };
//         // let (s, c) = add_with_carry(x, Field::from(0), carry);
//         let (s, c) = add_with_carry(out.items[k], Field::from(0), carry);
//         out.items[k] = s;
//         carry = c;
//     }
//     out
// }
fn mul_chunks_5x5_deferred(a: FieldElement256, b: FieldElement256) -> FieldElement512 {
    let zero = Field::from(0);

    // 1) accumulate raw 5x5 products into a 16-limb array
    let mut out = FieldElement512 { items: [zero; 2 * NUM_CHUNKS] };
    for i in 0..M2 {
        let ai = a.items[i];
        for j in 0..M2 {
            let bj = b.items[j];
            let (lo, hi) = mul_field32(ai, bj);
            out.items[i + j] = out.items[i + j] + lo;
            out.items[i + j + 1] = out.items[i + j + 1] + hi;
        }
    }
    // print("\nJust after first loop: raw a*b");
    // for i in 0..2 * NUM_CHUNKS {
    //     print("\nout.items[");
    //     print(i);
    //     print("] = ");
    //     print(out.items[i]);
    // }
    // 2) one single carry-propagate over all 16 limbs
    for _ in 0..M2 {
        let mut carry = zero;
        for k in 0..2 * NUM_CHUNKS {
            let (s, c) = add_with_carry(out.items[k], zero, carry);
            out.items[k] = s;
            carry = c;
        }
    }
    // print("\nJust after second loop: normalized a*b");
    // for i in 0..2 * NUM_CHUNKS {
    //     print("\nout.items[");
    //     print(i);
    //     print("] = ");
    //     print(out.items[i]);
    // }

    out
}

// (C) 4-limb addition of two NUM_CHUNKS/2-sized numbers --> fits in NUM_CHUNKS/2+1 limbs.
//     We pack result into a full FieldElement256, zeroing the rest.
fn add_chunks_4x4(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
    let mut out = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let zero = Field::from(0);
    let mut carry = zero;

    // add each limb
    for i in 0..M {
        let (s, c1) = add_with_carry(a.items[i], b.items[i], carry);
        out.items[i] = s;
        carry = c1;
    }
    // write final carry into the next limb
    out.items[M] = carry;
    // remaining limbs already zero
    out
}

// (D) Subtract two full 16-slot FieldElement512 values with borrow
// fn sub_chunks_8x8(a: FieldElement512, b: FieldElement512) -> FieldElement512 {
//     let mut out = FieldElement512 { items: [Field::from(0); 2*NUM_CHUNKS] };

//     let mut borrow = Field::from(0);

//     for i in 0..(2*NUM_CHUNKS) {
//         let (d, br): (Field, Field) = sub_with_borrow_field_chunk_size(a.items[i], b.items[i], borrow);
//         out.items[i] = d;
//         borrow = br;
//     }
//     out
// }
fn sub_chunks_8x8(a: FieldElement512, b: FieldElement512) -> FieldElement512 {
    let mut out = FieldElement512 { items: [Field::from(0); 2 * NUM_CHUNKS] };
    let mut borrow = Field::from(0);

    for i in 0..(2 * NUM_CHUNKS) {
        // Call the *exact** helper* that gives (chunk, borrow_out)
        let (chunk, new_borrow) = sub_with_borrow_field_chunk_size(a.items[i], b.items[i], borrow);
        // if i == 3 {
        // print("\n sub_chunks_8x8");
        // print(" i = ");
        // print(i);
        // print(" left = ");
        // print(a.items[i]);
        // print(" right = ");
        // print(b.items[i]);
        // print(" chunk = ");
        // print(chunk);
        // print(" borrow = ");
        // print(borrow);
        // }
        // if i == 4 {
        //     print("\n sub_chunks_8x8 4: ");
        //                 print("left = ");
        //     print(a.items[i]);
        //     print(" right = ");
        //     print(b.items[i]);
        //     print(" chunk = ");
        //     print(chunk);
        //     print(" borrow = ");
        //     print(borrow);
        // }
        out.items[i] = chunk;
        borrow = new_borrow;
    }
    out
}

// (E) In-place add "addend" shifted left by `shift` chunks into `dst`
fn add_shifted(dst: &mut FieldElement512, addend: FieldElement512, shift: u32) {
    let zero = Field::from(0);
    let mut carry = zero;
    for i in 0..(2 * NUM_CHUNKS) {
        let ai = if i >= shift {
            addend.items[i - shift]
        } else {
            zero
        };
        // add ai + carry
        let (s, c1) = add_with_carry(dst.items[i], ai, carry);
        dst.items[i] = s;
        carry = c1;
    }
}

// (F) One final full-length carry-propagate to normalize any outstanding carries
fn normalize(dst: &mut FieldElement512) {
    let zero = Field::from(0);
    let mut carry = zero;
    for i in 0..(2 * NUM_CHUNKS) {
        let (s, c1) = add_with_carry(dst.items[i], zero, carry);
        dst.items[i] = s;
        carry = c1;
    }
}

fn add_chunks_5x5(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
    let mut out = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut carry = Field::from(0);

    // now sum over 5 limbs, not 4!
    for i in 0..M2 {
        let (s, c) = add_with_carry(a.items[i], b.items[i], carry);
        out.items[i] = s;
        carry = c;
    }
    // write the final carry into the 6th position
    out.items[M2] = carry;
    out
}

// (G) The top-level 8x8 Karatsuba multiply
pub fn mul_chunks_8x8(a: FieldElement256, b: FieldElement256) -> FieldElement512 {
    // 1) split into low/high halves
    let (a_lo, a_hi) = split4(a);
    let (b_lo, b_hi) = split4(b);

    // 2) three 4x4 multiplies
    // let z0 = mul_chunks_4x4(a_lo, b_lo);
    // let z2 = mul_chunks_4x4(a_hi, b_hi);
    let z0 = mul_chunks_5x5_deferred(a_lo, b_lo);
    let z2 = mul_chunks_5x5_deferred(a_hi, b_hi);

    // 3) (a_lo + a_hi) * (b_lo + b_hi)
    // let sa = add_chunks_4x4(a_lo, a_hi);
    // let sb = add_chunks_4x4(b_lo, b_hi);
    // let z1 = mul_chunks_4x4(sa, sb);
    let sa = add_chunks_5x5(a_lo, a_hi);
    let sb = add_chunks_5x5(b_lo, b_hi);
    let z1 = mul_chunks_5x5_deferred(sa, sb);

    // 4) middle = z1 - z0 - z2
    let mut mid = sub_chunks_8x8(z1, z0);
    mid = sub_chunks_8x8(mid, z2);

    // 5) assemble: z0 + (mid << 4) + (z2 << 8)
    let mut out = z0;
    add_shifted(&mut out, mid, NUM_CHUNKS / 2);
    add_shifted(&mut out, z2, NUM_CHUNKS);

    // // shift the "middle" term left by 5 limbs
    // add_shifted(&mut out, mid, M2);

    // // shift the high term left by 10 limbs
    // add_shifted(&mut out, z2, 2 * M2);

    // 6) one final normalization pass
    // normalize(&mut out);
    let mut carry = Field::from(0);
    for k in 0..(2 * NUM_CHUNKS) {
        let (s, c) = add_with_carry(out.items[k], Field::from(0), carry);
        out.items[k] = s;
        carry = c;
    }

    out
}

fn mul_chunks_9x9(a: FieldElement512Partial, b: FieldElement512Partial) -> FieldElement512 {
    let mut out = FieldElement512 {
        items: [Field::from(0); 2 * NUM_CHUNKS], // Or 17 chunks if needed
    };

    for i in 0..(NUM_CHUNKS + 1) {
        for j in 0..(NUM_CHUNKS + 1) {
            if i + j < (2 * NUM_CHUNKS - 1) {
                let (lo, hi): (Field, Field) = mul_field32(a.items[i], b.items[j]);

                let (sum_lo, carry1): (Field, Field) =
                    add_with_carry(out.items[i + j], lo, Field::from(0));
                let (sum_hi, carry2): (Field, Field) =
                    add_with_carry(out.items[i + j + 1], hi, carry1);

                out.items[i + j] = sum_lo;
                out.items[i + j + 1] = sum_hi;

                let mut carry = carry2;

                for offset in 0..(2 * NUM_CHUNKS) {
                    // Calculate the target index.
                    let k = i + j + 2 + offset;
                    // Only perform an update if k is in range.
                    if k < 2 * NUM_CHUNKS {
                        let (sum, new_carry) = add_with_carry(out.items[k], Field::from(0), carry);
                        out.items[k] = sum;
                        carry = new_carry;
                    }
                }
            }
        }
    }

    out
}

// This unconstrained helper divides a u64 (provided as a Field) by 2,
// returning the quotient and remainder as Field values.
unconstrained fn div_by_two_helper(current: Field) -> (Field, Field) {
    let current_bits: [u1; 33] = current.to_le_bits();
    let r_bits = current_bits[0];
    let r_field = if r_bits == 1 {
        Field::from(1)
    } else {
        Field::from(0)
    };
    let q_field = (current - r_field) / 2;
    (q_field, r_field)
}

unconstrained fn div_by_two(a: FieldElement256) -> FieldElement256 {
    let mut result = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut carry = Field::from(0);

    // Process chunks in descending order.
    for i in 0..NUM_CHUNKS {
        // Compute index in reverse order: highest chunk first.
        let j = (NUM_CHUNKS - 1 - i);
        // current = (carry * BASE) + a.items[j]
        let current = carry * CARRY_BASE + a.items[j];
        // Use the helper to compute quotient q and remainder r when dividing current by 2.
        let (q, r) = unsafe { div_by_two_helper(current) };
        result.items[j] = q;
        carry = r;
    }

    result
}

// Let's just binary search for the quotient q and remainder r such that pq + r = x
unconstrained fn basic_reduce(x: FieldElement512) -> (FieldElement256, FieldElement256) {
    let mut high = p;
    let mut low = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut q = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut r = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut done: bool = false;
    for _ in 0..NUM_BITS {
        let mid = div_by_two(add_256(low, high).0);
        let prod_mid = mul_chunks_8x8_deferred(mid, p);
        let (mid_plus_one, _): (FieldElement256, Field) = add_256(mid, ONE_P);
        let prod_next = mul_chunks_8x8_deferred(mid_plus_one, p);
        if !done {
            if (is_greater_than_eq_512(x, prod_mid) & is_greater_than_512(prod_next, x)) {
                // If (mid + 1) * p > x >= p * mid, then we can stop
                q = mid;
                let out = sub_field512(x, prod_mid);
                r = field512_to_256(out.0);
                done = true;
            } else if is_greater_than_eq_512(x, prod_next) {
                // This is the case where we search the higher half
                low = mid_plus_one;
            } else {
                // This is the case where we search the lower half
                high = mid;
            }
        }
    }

    (q, r)
}

// Let's just binary search for the quotient q and remainder r such that pq + r = x
unconstrained fn arithmetic_div_chunk_size(dividend: Field) -> (Field, Field) {
    let numerator_u128 = unsafe { field_to_u128(dividend) };
    let q = numerator_u128 >> (CHUNK_SIZE as u128);
    let quotient = unsafe { field_from_u128(q) };
    let remainder = dividend - (quotient * CARRY_BASE);
    (quotient, remainder)
    // let mut high = divisor;
    // let mut low = 0;
    // let mut q = 0;
    // let mut r = 0;
    // let mut done: bool = false;
    // for _ in 0..NUM_BITS {
    //     let mid = div_by_two(add_256(low, high).0);
    //     let prod_mid = mul_chunks_8x8(mid, p);
    //     let (mid_plus_one, _): (FieldElement256, Field) = add_256(mid, ONE_P);
    //     let prod_next = mul_chunks_8x8(mid_plus_one, p);
    //     if !done {
    //         if (is_greater_than_eq_512(x, prod_mid) & is_greater_than_512(prod_next, x)) {
    //             // If (mid + 1) * p > x >= p * mid, then we can stop
    //             q = mid;
    //             let out = sub_field512(x, prod_mid);
    //             r = field512_to_256(out.0);
    //             done = true;
    //         } else if is_greater_than_eq_512(x, prod_next) {
    //             // This is the case where we search the higher half
    //             low = mid_plus_one;
    //         } else {
    //             // This is the case where we search the lower half
    //             high = mid;
    //         }
    //     }
    // }

    // (q, r)
}

fn barrett_reduce(x: FieldElement512) -> FieldElement256 {
    // Step 1: Extract the top (NUM_CHUNKS+1) chunks from x.
    let mut x_high = FieldElement512Partial { items: [Field::from(0); NUM_CHUNKS + 1] };
    // We take chunks from index (NUM_CHUNKS - 1) up through the end.
    for i in 0..(NUM_CHUNKS + 1) {
        x_high.items[i] = x.items[i + NUM_CHUNKS - 1];
    }

    // Step 2: Compute q_full = x_high * mu using our fixed 9x9 multiplication.
    let q_full = mul_chunks_9x9(x_high, MU); // q_full is assumed to be a FieldElement512
    let mut q = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    // We take the upper NUM_CHUNKS chunks of q_full (i.e. indices NUM_CHUNKS..2*NUM_CHUNKS).
    for i in 0..NUM_CHUNKS {
        q.items[i] = q_full.items[i + NUM_CHUNKS];
    }

    // Step 3: Compute r = x - q * p.
    let qp = mul_chunks_8x8(q, p); // qp is a FieldElement512.
    let mut r = FieldElement512 { items: [Field::from(0); 2 * NUM_CHUNKS] };
    let mut borrow = Field::from(0);
    for i in 0..(2 * NUM_CHUNKS) {
        let (diff, new_borrow): (Field, Field) =
            sub_with_borrow_field_chunk_size(x.items[i], qp.items[i], borrow);
        r.items[i] = diff;
        borrow = new_borrow;
    }

    // Step 4: Let r_lo be the lower NUM_CHUNKS chunks of r.
    let mut r_lo = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    for i in 0..NUM_CHUNKS {
        r_lo.items[i] = r.items[i];
    }

    // Step 5: Conditionally subtract p once.
    let (r_minus_p, underflow): (FieldElement256, Field) = sub_field256(r_lo, p);
    let mut result = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    // underflow will be 0 if r_lo >= p (i.e. the subtraction worked without borrow),
    // so we choose r_minus_p; otherwise we choose r_lo.
    for i in 0..NUM_CHUNKS {
        result.items[i] =
            r_minus_p.items[i] * (Field::from(1) - underflow) + r_lo.items[i] * underflow;
    }

    result
}

pub fn mul_mod_p(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
    // Step 1: full 512-bit product
    let product = mul_chunks_8x8_deferred(a, b);

    if is_greater_than_512(p_512, product) {
        // If product is less than p, we can return it directly
        field512_to_256(product)
    } else {
        // let reduced = barrett_reduce(product);
        // Step 2: Simple reduction mod p
        let (q, r): (FieldElement256, FieldElement256) = unsafe { basic_reduce(product) };
        let out = add_512(mul_chunks_8x8_deferred(q, p), field256_to_512(r));
        assert(is_equal_512(out.0, product));

        r
    }
}

// Invert a 256-bit integer
pub unconstrained fn get_inv_mod_p(a: FieldElement256) -> FieldElement256 {
    let mut result = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    result.items[0] = Field::from(1);

    let mut base = a;

    for bit_index in 0..NUM_BITS {
        let chunk_index = bit_index / CHUNK_SIZE;
        let bit_offset = bit_index % CHUNK_SIZE;
        // Extract the bit at bit_index from a
        let bit_mask = field_from_u128(shift_left_u128(1, bit_offset as u64));
        let is_one = (P_MINUS_2.items[chunk_index] * bit_mask) / bit_mask;

        let should_multiply = is_one;
        if should_multiply == Field::from(0) {
            break;
        }
        // result = (should_multiply == 1) ? result * base : result
        let res_mul = mul_mod_p(result, base);

        let mut new_result = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
        for i in 0..NUM_CHUNKS {
            new_result.items[i] = res_mul.items[i] * should_multiply
                + result.items[i] * (Field::from(1) - should_multiply);
        }

        result = new_result;
        base = mul_mod_p(base, base);
    }

    result
}

// fn inv_mod_p(a: FieldElement256) -> FieldElement256 {
//     let a_inv = unsafe { get_inv_mod_p(a) };
//     assert(is_equal(mul_mod_p(a, a_inv), ONE_P));
//     a_inv
// }

// fn div_mod_p(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
//     let b_inv = inv_mod_p(b);
//     let res = mul_mod_p(a, b_inv);
//     assert(is_equal(mul_mod_p(a, b), mul_mod_p(res, b)));
//     res
// }

// ------ Now that we have all the field items,
// let's deal with the elliptic curve operations ------ //

pub struct ECPoint {
    x: FieldElement256,
    y: FieldElement256,
}

// Example elliptic curve parameters for a short Weierstrass form: y^2 = x^3 + A*x + B mod P
// Adjust these for the actual curve you want to work with:
global A: Field = 0; // Example: A = 0
// global B: Field = -17; // Example: B = 3 (like bn254's B)
global B: Field = Field::from(0) - Field::from(17);

// Example A coefficient for the curve y^2 = x^3 + A*x + B.
fn curve_A() -> FieldElement256 {
    let mut fe = zero_fe();
    fe.items[0] = A;
    fe
}

// Example B coefficient if needed in a circuit check
pub fn curve_B() -> FieldElement256 {
    // If B = 3, for instance, that means each chunk is zero except maybe the first is 3

    let mut fe = zero_fe();
    fe.items[0] = B;
    fe
}

// ------ Additional operations we might require for this field ------ //
// Hash function over the above curve -- do we need this?
// Checking for map-to-curve constraints

pub fn check_nonnative_map_to_curve_constraints(
    m: FieldElement256,
    x: FieldElement256,
    y: FieldElement256,
    z: FieldElement256,
    t: FieldElement256,
) -> bool {
    // let cond_1 = (x == (t + m * T));
    let m_times_t = mul_mod_p(m, NON_NATIVE_T);
    let t_plus_m_times_t = add_mod_p(t, m_times_t);
    let cond_1 = is_equal(x, t_plus_m_times_t);
    let z_sq = mul_mod_p(z, z);

    let cond_2 = is_equal(y, z_sq);

    let x_sq = mul_mod_p(x, x);
    // let f_x = (x_sq * x) + 3;
    let f_x = add_mod_p(mul_mod_p(x_sq, x), curve_B());

    let y_sq = mul_mod_p(y, y);

    let cond_3 = is_equal(y_sq, f_x);

    cond_1 & cond_2 & cond_3
}

// // // #[field(bn254)]
// fn main(m: FieldElement256, x: FieldElement256, y: FieldElement256, z: FieldElement256, t: FieldElement256) {
//     let check = check_nonnative_map_to_curve_constraints(m, x, y, z, t);
//     assert(check);
// }

// ----- Elliptic curve point operations ----- //

/// Check if a point is the "infinity point."
/// In affine coordinates, we don't have a formal "point at infinity,"
/// so we'll treat (0, 0) as a placeholder.
fn is_infinity(point: ECPoint) -> bool {
    is_equal(
        point.x,
        FieldElement256 { items: [Field::from(0); NUM_CHUNKS] },
    )
        & is_equal(
            point.y,
            FieldElement256 { items: [Field::from(0); NUM_CHUNKS] },
        )
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

#[test]
fn test_is_equal() {
    let a = FieldElement256 {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let b = FieldElement256 {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    assert(is_equal(a, b));
    assert(
        !is_equal(
            a,
            FieldElement256 {
                items: [
                    Field::from(2),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                ],
            },
        ),
    );
}

#[test]
fn test_is_equal512() {
    let a = FieldElement512 {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let b = FieldElement512 {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    assert(is_equal_512(a, b));
    assert(
        !is_equal_512(
            a,
            FieldElement512 {
                items: [
                    Field::from(2),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                    Field::from(0),
                ],
            },
        ),
    );
}

#[test]
fn test_nonnative_simple_add() {
    let one = FieldElement256 {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let three = FieldElement256 {
        items: [
            Field::from(3),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };
    let (sum, carry): (FieldElement256, Field) = add_256(one, two);
    assert(is_equal(sum, three));
}

#[test]
fn test_nonnative_sub() {
    let one = FieldElement256 {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let three = FieldElement256 {
        items: [
            Field::from(3),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let (diff, _): (FieldElement256, Field) = sub_field256(three, one);
    assert(is_equal(diff, two));
}

#[test]
fn test_nonnative_modular_add() {
    let one = FieldElement256 {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let three = FieldElement256 {
        items: [
            Field::from(3),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let sum = add_mod_p(one, two);
    assert(is_equal(sum, three));

    let bigger_sum = add_mod_p(p, two);
    assert(is_equal(bigger_sum, two));
}

#[test]
fn test_8x8_mul() {
    let one = FieldElement256 {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };
    let two_512 = FieldElement512 {
        items: [
            Field::from(2),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let prod: FieldElement512 = mul_chunks_8x8(one, two);

    assert(is_equal_512(prod, two_512));
}

#[test]
fn test_9x9_mul() {
    let one = FieldElement512Partial {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let two = FieldElement512Partial {
        items: [
            Field::from(2),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };
    let two_512 = FieldElement512 {
        items: [
            Field::from(2),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };
    let prod: FieldElement512 = mul_chunks_9x9(one, two);
    assert(is_equal_512(prod, two_512));
}

#[test]
fn test_divide_by_two_helper() {
    let zero = Field::from(0);
    let one = Field::from(1);
    let two = Field::from(2);
    let three = Field::from(3);
    let four = Field::from(4);

    let (q, r) = unsafe { div_by_two_helper(four) };
    assert(q.eq(two));
    assert(r.eq(zero));

    let (q, r) = unsafe { div_by_two_helper(three) };
    assert(q.eq(one));
    assert(r.eq(one));

    let (q, r) = unsafe { div_by_two_helper(one) };
    assert(q.eq(zero));
    assert(r.eq(one));
}

#[test]
fn test_add_with_carry_simple() {
    let (sum, carry) = add_with_carry(Field::from(3), Field::from(4), Field::from(0));
    assert(sum == Field::from(7));
    assert(carry == Field::from(0));
}

#[test]
fn test_add_with_carry_overflow() {
    // max chunk + 1 --> wrap to 0 + carry
    let max_chunk = CARRY_BASE - Field::from(1);
    let (sum, carry) = add_with_carry(max_chunk, Field::from(1), Field::from(0));
    assert(sum == Field::from(0));
    assert(carry == Field::from(1));
}

#[test]
fn test_add_with_carry_with_carry_in() {
    // 0 + 0 + 1 --> 1, no further carry
    let (sum, carry) = add_with_carry(Field::from(0), Field::from(0), Field::from(1));
    assert(sum == Field::from(1));
    assert(carry == Field::from(0));
}

#[test]
fn test_sub_with_borrow_simple() {
    // 5 - 3 --> 2, no borrow
    let (chunk, borrow) =
        sub_with_borrow_field_chunk_size(Field::from(5), Field::from(3), Field::from(0));
    assert(chunk == Field::from(2));
    assert(borrow == Field::from(0));
}

#[test]
fn test_sub_with_borrow_underflow() {
    // 3 - 5 --> CARRY_BASE - 2, with borrow
    let (chunk, borrow) =
        sub_with_borrow_field_chunk_size(Field::from(3), Field::from(5), Field::from(0));
    assert(chunk == (CARRY_BASE - Field::from(2)));
    assert(borrow == Field::from(1));
}

#[test]
fn test_sub_with_borrow_field_chunk_size_with_borrow_in() {
    // (3 - 2) - 1 --> 0, no borrow
    let (chunk, borrow) =
        sub_with_borrow_field_chunk_size(Field::from(3), Field::from(2), Field::from(1));
    assert(chunk == Field::from(0));
    assert(borrow == Field::from(0));
}

#[test]
fn test_add_chunks_5x5_simple() {
    // [1,2,3,4,5] + [5,4,3,2,1] = [6,6,6,6,6], carry = 0
    let a = FieldElement256 {
        items: [
            Field::from(1),
            Field::from(2),
            Field::from(3),
            Field::from(4),
            Field::from(5),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };
    let b = FieldElement256 {
        items: [
            Field::from(5),
            Field::from(4),
            Field::from(3),
            Field::from(2),
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };
    let c = add_chunks_5x5(a, b);
    // check the 5 limbs
    for i in 0..5 {
        assert(c.items[i] == Field::from(6));
    }
    // final carry limb
    assert(c.items[5] == Field::from(0));
}

#[test]
fn test_mul_chunks_5x5_deferred_simple() {
    // (1 + B)^2 = 1 + 2B + B^2
    let a = FieldElement256 {
        items: [
            Field::from(1),
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };
    let b = a;
    let out = mul_chunks_5x5_deferred(a, b);
    // out[0] = 1, out[1] = 2, out[2] = 1, rest = 0
    assert(out.items[0] == Field::from(1));
    assert(out.items[1] == Field::from(2));
    assert(out.items[2] == Field::from(1));
    // check the rest up to OUT2 = 10 limbs
    let out_len = 2 * (NUM_CHUNKS / 2 + 1);
    for k in 3..out_len {
        assert(out.items[k] == Field::from(0));
    }
}

#[test]
fn test_mul_mod_p() {
    let one = FieldElement256 {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let prod: FieldElement256 = mul_mod_p(one, two);

    assert(is_equal(prod, two));

    let (minus_one, _): (FieldElement256, Field) = sub_field256(p, one);
    let (minus_two, _): (FieldElement256, Field) = sub_field256(p, two);

    let prod: FieldElement256 = mul_mod_p(minus_one, minus_two);
    assert(is_equal(prod, two));
}

#[test]
fn test_is_infinity() {
    let inf = ECPoint { x: zero_fe(), y: zero_fe() };
    assert(is_infinity(inf), "Expected (0,0) to be infinity.");

    // A dummy point with x != 0 or y != 0
    // (In practice, you'll construct FieldElement256 properly.)
    let non_inf = ECPoint { x: zero_fe(), y: curve_B()/* some non-zero FieldElement256 */ };
    assert(!is_infinity(non_inf), "Expected non_inf to not be infinity.");
}

#[test]
fn test_mul_chunks_5x5_deferred_geometric() {
    // a = 1 + B + B^2 + B^3 + B^4
    let mut a = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    for i in 0..5 {
        a.items[i] = Field::from(1);
    }
    // (1 + B + ... + B^4)^2 =
    //   1 + 2B + 3B^2 + 4B^3 + 5B^4 + 4B^5 + 3B^6 + 2B^7 + B^8
    let out = mul_chunks_5x5_deferred(a, a);

    let expected = [1, 2, 3, 4, 5, 4, 3, 2, 1, 0];
    for k in 0..(2 * (NUM_CHUNKS / 2 + 1)) {
        assert(out.items[k] == Field::from(expected[k]));
    }
}

#[test]
fn test_mul_chunks_5x5_deferred_arbitrary() {
    // a = [1,2,3,4,5], b = [6,7,8,9,10]
    let mut a = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut b = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    for i in 0..5 {
        a.items[i] = Field::from(i + 1);
    }
    for i in 0..5 {
        b.items[i] = Field::from(i + 6);
    }
    // Convolution:
    // c[0]=1*6=6
    // c[1]=1*7+2*6=19
    // c[2]=1*8+2*7+3*6=40
    // c[3]=1*9+2*8+3*7+4*6=70
    // c[4]=1*10+2*9+3*8+4*7+5*6=110
    // c[5]=2*10+3*9+4*8+5*7=114
    // c[6]=3*10+4*9+5*8=106
    // c[7]=4*10+5*9=85
    // c[8]=5*10=50
    // c[9]=0
    let out = mul_chunks_5x5_deferred(a, b);
    let expected = [6, 19, 40, 70, 110, 114, 106, 85, 50, 0];
    for k in 0..expected.len() {
        assert(out.items[k] == Field::from(expected[k]));
    }
}

/// Test a full carry-chain when every limb is at maximum (CARRY_BASE-1).
#[test]
fn test_add_chunks_5x5_max_vals() {
    // build [max,max,max,max,max]
    let max = CARRY_BASE - Field::from(1);
    let a = FieldElement256 {
        items: [max, max, max, max, max, Field::from(0), Field::from(0), Field::from(0)],
    };
    let b = a;

    let c = add_chunks_5x5(a, b);

    // limb 0: (max + max + 0) = 2*(2^32-1)-->chunk = 2^32-2, carry=1
    assert(c.items[0] == CARRY_BASE - Field::from(2));
    // limbs 1-4: each sees (max+max+1)=2^33-1 --> chunk=2^32-1, carry=1
    for i in 1..5 {
        assert(c.items[i] == CARRY_BASE - Field::from(1));
    }
    // final carry into limb 5
    assert(c.items[5] == Field::from(1));
}

/// Test a mixed-pattern that generates a single carry then dies out.
#[test]
fn test_add_chunks_5x5_mixed_chain() {
    // a = [1, max, 0,0,0],  b = [max,1, 0,0,0]
    // CARRY_BASE = 2^32
    let max = CARRY_BASE - Field::from(1);
    let mut a = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut b = a;
    a.items[0] = Field::from(1);
    a.items[1] = max;
    b.items[0] = max;
    b.items[1] = Field::from(1);

    let c = add_chunks_5x5(a, b);

    // limb 0: 1 + (2^32-1) + 0 = 2^32-->chunk=0, carry=1
    assert(c.items[0] == Field::from(0));
    // limb 1: (2^32-1) + 1 + 1 = 2^32+1-->chunk=1, carry=1
    assert(c.items[1] == Field::from(1));
    // limb 2: 0 + 0 + 1 = 1-->chunk=1, carry=0
    assert(c.items[2] == Field::from(1));
    // no more carry, so limbs 3-4 stay zero
    assert(c.items[3] == Field::from(0));
    assert(c.items[4] == Field::from(0));
    // and final carry limb is 0
    assert(c.items[5] == Field::from(0));
}

/// Test some arbitrary but known vectors.
#[test]
fn test_add_chunks_5x5_arbitrary() {
    // a = [3, 7, 1, 5, 2], b = [4, 9, 8, 6, 3]
    let vals_a = [3, 7, 1, 5, 2];
    let vals_b = [4, 9, 8, 6, 3];
    let mut a = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut b = a;
    for i in 0..5 {
        a.items[i] = Field::from(vals_a[i]);
        b.items[i] = Field::from(vals_b[i]);
    }

    // hand-compute the sums + carries:
    // 0: 3+4=7, c=0
    // 1: 7+9=16,c=0
    // 2: 1+8=9, c=0
    // 3: 5+6=11,c=0
    // 4: 2+3=5, c=0
    let c = add_chunks_5x5(a, b);
    let expected = [7, 16, 9, 11, 5, 0];
    for i in 0..6 {
        assert(c.items[i] == Field::from(expected[i]));
    }
}

/// 1) A full 5-limb carry chain: every limb max + max --> each produces a carry
#[test]
fn test_add_chunks_5x5_full_chain() {
    let max = CARRY_BASE - Field::from(1);
    let a = FieldElement256 {
        items: [max, max, max, max, max, Field::from(0), Field::from(0), Field::from(0)],
    };
    let b = a;

    let c = add_chunks_5x5(a, b);
    // Limb 0: 2*(2^32-1) = 2^33 - 2 --> chunk=2^32-2, carry=1
    assert(c.items[0] == CARRY_BASE - Field::from(2));
    // Limbs 1-4: each (2^32-1)+(2^32-1)+1 = 2^33-1 --> chunk=2^32-1, carry=1
    for i in 1..5 {
        assert(c.items[i] == CARRY_BASE - Field::from(1));
    }
    // Final carry into limb 5
    assert(c.items[5] == Field::from(1));
}

/// 2) A single-carry that dies out: carry only at limb 0-->1-->2, then stops
#[test]
fn test_add_chunks_5x5_single_chain() {
    let max = CARRY_BASE - Field::from(1);
    // a = [1, max, 0,0,0], b = [max,1,0,0,0]
    let mut a = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut b = a;
    a.items[0] = Field::from(1);
    a.items[1] = max;
    b.items[0] = max;
    b.items[1] = Field::from(1);

    let c = add_chunks_5x5(a, b);
    // 0: 1 + (2^32-1) = 2^32 --> chunk=0, carry=1
    assert(c.items[0] == Field::from(0));
    // 1: (2^32-1) + 1 + 1 = 2^32 +1 --> chunk=1, carry=1
    assert(c.items[1] == Field::from(1));
    // 2: 0 + 0 + 1 = 1 --> chunk=1, carry=0
    assert(c.items[2] == Field::from(1));
    // 3,4: no carry, remain zero
    assert(c.items[3] == Field::from(0));
    assert(c.items[4] == Field::from(0));
    // final carry limb = 0
    assert(c.items[5] == Field::from(0));
}

/// 3) A mixed arbitrary pattern with carries in the middle
#[test]
fn test_add_chunks_5x5_mixed_pattern_corrected() {
    // a = [0xffffffff, 2, 0xfffffff0, 5, 1]
    // b = [5,          0xfffffff0, 3,         0, 2]
    let max = CARRY_BASE - Field::from(1);
    let mut a = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut b = a;
    let vals_a = [max, Field::from(2), Field::from(0xfffffff0), Field::from(5), Field::from(1)];
    let vals_b = [Field::from(5), Field::from(0xfffffff0), Field::from(3), Field::from(0), max];
    for i in 0..5 {
        a.items[i] = vals_a[i];
        b.items[i] = vals_b[i];
    }

    let c = add_chunks_5x5(a, b);

    // limb 0:  (2^32-1) + 5      = 2^32 + 4  --> chunk=4, carry=1
    assert(c.items[0] == Field::from(4));

    // limb 1:  2 + (2^32-16) + 1 = 2^32 - 13 --> chunk=CARRY_BASE-13, carry=0
    let expected_lo1 = CARRY_BASE - Field::from(13);
    assert(c.items[1] == expected_lo1);

    // limb 2:  (2^32-16) + 3 + 0 = 2^32 - 13 --> same
    assert(c.items[2] == expected_lo1);

    // limb 3:  5 + 0 + 0 = 5
    assert(c.items[3] == Field::from(5));

    // limb 4:  1 + max = 2^32 --> chunk=0, carry=1
    assert(c.items[4] == Field::from(0));

    // limb 5:  final carry = 1
    assert(c.items[5] == Field::from(1));
}

/// Test sub_chunks_8x8: zero minus zero --> all zero
#[test]
fn test_sub_chunks_8x8_zero() {
    let a = FieldElement512 { items: [Field::from(0); 2 * NUM_CHUNKS] };
    let b = a;
    let c = sub_chunks_8x8(a, b);
    for i in 0..2 * NUM_CHUNKS {
        assert(c.items[i] == Field::from(0));
    }
}

/// Test sub_chunks_8x8 underflow: 0 - 1 --> all limbs = BASE-1
#[test]
fn test_sub_chunks_8x8_underflow() {
    let mut a = FieldElement512 { items: [Field::from(0); 2 * NUM_CHUNKS] };
    let mut b = a;
    b.items[0] = Field::from(1);
    let c = sub_chunks_8x8(a, b);
    for i in 0..2 * NUM_CHUNKS {
        assert(c.items[i] == CARRY_BASE - Field::from(1));
    }
}

/// Test add_shifted: shifting a simple pattern by k limbs
#[test]
fn test_add_shifted_simple() {
    let mut out = FieldElement512 { items: [Field::from(0); 2 * NUM_CHUNKS] };
    // pattern = [1,2,3,4]
    let mut pat = FieldElement512 { items: [Field::from(0); 2 * NUM_CHUNKS] };
    for i in 0..4 {
        pat.items[i] = Field::from((i + 1));
    }
    let shift = 3;
    add_shifted(&mut out, pat, shift);
    // check that out[shift + i] == pat[i]
    for i in 0..4 {
        assert(out.items[shift + i] == Field::from((i + 1) as u8));
    }
    // everything else stays zero
    for i in 0..shift {
        assert(out.items[i] == Field::from(0));
    }
    for i in (shift + 4)..(2 * NUM_CHUNKS) {
        assert(out.items[i] == Field::from(0));
    }
}

/// End-to-end: compare karatsuba vs the original schoolbook on a nontrivial input
#[test]
fn test_mul_chunks_8x8_compare() {
    // a = [1,2,3,4,5,6,7,8], b = [8,7,6,5,4,3,2,1]
    let mut a = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut b = a;
    for i in 0..NUM_CHUNKS {
        a.items[i] = Field::from((i + 1) as u8);
        b.items[i] = Field::from((NUM_CHUNKS - i) as u8);
    }
    let sb = mul_chunks_8x8_schoolbook(a, b);
    let kp = mul_chunks_8x8(a, b);
    for i in 0..(2 * NUM_CHUNKS) {
        assert(sb.items[i] == kp.items[i]);
    }
}

#[test]
fn test_mul_large() {
    let one = FieldElement256 {
        items: [
            Field::from(1),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
            Field::from(0),
        ],
    };

    let (minus_one, _): (FieldElement256, Field) = sub_field256(p, one);
    let (minus_two, _): (FieldElement256, Field) = sub_field256(p, two);
    let prod: FieldElement512 = mul_chunks_8x8(minus_one, minus_two);
    let prod_schoolbook: FieldElement512 = mul_chunks_8x8_schoolbook(minus_one, minus_two);

    assert(is_equal_512(prod, prod_schoolbook));

    let prod_deferred: FieldElement512 = mul_chunks_8x8_deferred(minus_one, minus_two);
    assert(is_equal_512(prod_deferred, prod_schoolbook));
}

#[test]
fn debug_karatsuba_mid() {
    // Reproduce exactly your failing test's inputs:
    let a = FieldElement256 {
        items: [
            Field::from(0xd87cfd46),
            Field::from(0x3c208c16),
            Field::from(0x6871ca8d),
            Field::from(0x97816a91),
            Field::from(0x8181585d),
            Field::from(0xb85045b6),
            Field::from(0xe131a029),
            Field::from(0x30644e72),
        ],
    };
    let b = FieldElement256 {
        items: [
            Field::from(0xd87cfd45),
            Field::from(0x3c208c16),
            Field::from(0x6871ca8d),
            Field::from(0x97816a91),
            Field::from(0x8181585d),
            Field::from(0xb85045b6),
            Field::from(0xe131a029),
            Field::from(0x30644e72),
        ],
    };

    // 1) split
    let (a_lo, a_hi) = split4(a);
    let (b_lo, b_hi) = split4(b);
    print("\na_lo = ");
    print(a_lo.items);
    print("\na_hi = ");
    print(a_hi.items);
    print("\nb_lo = ");
    print(b_lo.items);
    print("\nb_hi = ");
    print(b_hi.items);

    // 2) partial products
    let z0 = mul_chunks_5x5_deferred(a_lo, b_lo);
    let z2 = mul_chunks_5x5_deferred(a_hi, b_hi);
    print("\nz0    = ");
    print(z0.items);
    print("\nz2    = ");
    print(z2.items);

    // 3) half-sums
    let sa = add_chunks_5x5(a_lo, a_hi);
    let sb = add_chunks_5x5(b_lo, b_hi);
    print("\nsa    = ");
    print(sa.items);
    print("\nsb    = ");
    print(sb.items);

    // 4) z1
    let z1 = mul_chunks_5x5_deferred(sa, sb);
    print("\nz1    = ");
    print(z1.items);

    // 5) mid = z1 - z0 - z2
    let mid1 = sub_chunks_8x8(z1, z0);
    print("\nmid1  = ");
    print(mid1.items);
    let mid2 = sub_chunks_8x8(mid1, z2);
    print("\nmid2  = ");
    print(mid2.items);
}
