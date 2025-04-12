use dep::std::field::bn254;
use dep::std::hash::poseidon;
use dep::std::hash::blake2s;
use dep::std::hash::blake3;
use dep::std::hash::pedersen_hash;
use dep::std::runtime::is_unconstrained;
global T: Field = 256;


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

struct FieldElement512 {    
    items: [Field; 2 * NUM_CHUNKS]
}

struct FieldElement512Partial {    
    items: [Field; NUM_CHUNKS + 1]
}

fn u32_arr_to_field_const(arr: [[u8; CHUNK_SIZE_BYTES]; NUM_CHUNKS]) -> FieldElement256 {
    let mut res = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    for i in 0..NUM_CHUNKS {
        res.items[i] = Field::from_le_bytes::<4>(arr[i]);
    }
    res
}

fn u32_arr_to_field_const257(arr: [[u8; CHUNK_SIZE_BYTES]; NUM_CHUNKS + 1]) -> FieldElement512Partial {
    let mut res = FieldElement512Partial { items: [Field::from(0); NUM_CHUNKS + 1] };
    for i in 0..NUM_CHUNKS+1 {
        res.items[i] = Field::from_le_bytes::<4>(arr[i]);
    }
    res
}

fn field256_to_512(elt: FieldElement256) -> FieldElement512 {
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

global p_le_bytes = [
        [71, 253, 124, 216],
        [22, 140, 32, 60],
        [141, 202, 113, 104],
        [145, 106, 129, 151],
        [93, 88, 129, 129],
        [182, 69, 80, 184],
        [41, 160, 49, 225],
        [114, 78, 100, 48],
    ];

global mu_le_bytes = [
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

// global p = FieldElement256 { 
//     items: [
//         Field::from(0xd87cfd47), Field::from(0x3c208c16), // limb0 (low, high)
//         Field::from(0x6871ca8d), Field::from(0x97816a91), // limb1
//         Field::from(0x8181585d), Field::from(0xb85045b6), // limb2
//         Field::from(0xe131a029), Field::from(0x30644e72), // limb3
//     ],
// };
global p = u32_arr_to_field_const(p_le_bytes);


global p_512 = field256_to_512(p);

global MU = u32_arr_to_field_const257(mu_le_bytes);



global P_MINUS_2 = FieldElement256 {
    items: [
        Field::from(0xd87cfd45), Field::from(0x3c208c16),
        Field::from(0x6871ca8d), Field::from(0x97816a91),
        Field::from(0x8181585d), Field::from(0xb85045b6),
        Field::from(0xe131a029), Field::from(0x30644e72),
    ],
};

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

unconstrained fn field_to_u128(x: Field) -> U128 {
    
    let s = U128::from_integer(x);

    s
}

unconstrained fn field_from_u128(x: U128) -> Field {

    x.to_integer()
}

unconstrained fn split_u128(x: U128) -> (U128, U128) {
    let chunk_mod_128 = U128::from_integer(1) << 32;
    let lo = x % chunk_mod_128;
    let hi = x / chunk_mod_128;
    (lo, hi)
}

unconstrained fn shift_right_u128(x: U128, s: u64) -> U128 {
    // Decompose the shift: how many whole bytes and a remainder (in bits)
    let num_shifts: u64 = s / 8;
    let rem: u8 = (s % 8) as u8;
    let mut result: U128 = x;
    // We unroll the loop to a fixed length (here, 16 iterations, which is safe since 16*8 = 128)
    for i in 0..16 {
        if i < num_shifts {
            result = result >> 8;
        }
    }
    // Then shift by the remaining bits (rem < 8, so this shift is allowed)
    result = result >> rem;
    result
}

unconstrained fn shift_left_u128(x: U128, s: u64) -> U128 {
    // Decompose the shift: how many whole bytes and a remainder (in bits)
    let num_shifts: u64 = s / 8;
    let rem: u8 = (s % 8) as u8;
    let mut result: U128 = x;
    let u128_256 = U128::from_integer(256);
    // We unroll the loop to a fixed length (here, 16 iterations, which is safe since 16*8 = 128)
    for i in 0..16 {
        if i < num_shifts {
            result = result * u128_256;
        }
    }
    // Then shift by the remaining bits (rem < 8, so this shift is allowed)
    result = result << rem;
    result
}

fn is_greater_or_equal(a: FieldElement256, b: FieldElement256) -> bool {
    let mut result = false;
    let mut equal = true;

    // Compare chunks starting from the most significant limb explicitly
    for j in 0..NUM_CHUNKS {
        let i = NUM_CHUNKS - 1 - j;
        result = result + (equal * (b.items[i].lt(a.items[i])));
        equal = equal * (a.items[i].eq(b.items[i]));
    }
    result + equal
}

fn is_greater_than(a: FieldElement256, b: FieldElement256) -> bool {
    let mut result = false;
    let mut equal = true;

    // Compare chunks starting from the most significant limb explicitly
    for j in 0..NUM_CHUNKS {
        let i = NUM_CHUNKS - 1 - j;
        result = result + (equal * (b.items[i].lt(a.items[i])));
        equal = equal * (a.items[i].eq(b.items[i]));
    }
    result
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

fn is_greater_than_512(a: FieldElement512, b: FieldElement512) -> bool {
    let mut result = false;
    let mut equal = true;

    // Compare chunks starting from the most significant limb explicitly
    for j in 0..NUM_CHUNKS*2 {
        let i = (2 * NUM_CHUNKS) - 1 - j;
        result = result + (equal * (b.items[i].lt(a.items[i])));
        equal = equal * (a.items[i].eq(b.items[i]));
    }
    result
}

fn is_greater_than_eq_512(a: FieldElement512, b: FieldElement512) -> bool {
    let mut result = false;
    let mut equal = true;

    // Compare chunks starting from the most significant limb explicitly
    for j in 0..NUM_CHUNKS*2 {
        let i = (2 * NUM_CHUNKS) - 1 - j;
        result = result + (equal * (b.items[i].lt(a.items[i])));
        equal = equal * (a.items[i].eq(b.items[i]));
    }
    result + equal
}

fn is_equal_512(a: FieldElement512, b: FieldElement512) -> bool {
    let mut equal = true;

    // Compare chunks starting from the most significant limb explicitly
    for j in 0..NUM_CHUNKS * 2 {
        let i = NUM_CHUNKS * 2 - 1 - j;
        equal = equal * (a.items[i].eq(b.items[i]));
    }
    equal
}



fn add_with_carry_basic(a: Field, b: Field) -> (Field, Field) {
    // Add two CHUNK_SIZE-bit integers with an incoming carry bit
    // Input:
    //   a, b: Field elements to be added
    // Output:
    //   (sum: Field, carry_out: Field)
    
    let sum_ab = a + b;
    // let carry_out = sum_ab / CARRY_BASE;
    let carry_out = if !sum_ab.lt(CARRY_BASE) { Field::from(1) } else { Field::from(0) };
    // If the sum is greater than 2^CHUNK_SIZE - 1, we have an overflow
    // and need to set the carry_out to 1
    
    let chunk: Field = sum_ab - carry_out * CARRY_BASE;
    (chunk, carry_out)
}

// Add two CHUNK_SIZE-bit integers with an incoming carry bit
// Input:
//   a, b: Field elements to be added
//   carry_in: incoming carry bit (0 or 1)
// Output:
//   (sum: Field, carry_out: Field)
fn add_with_carry(a: Field, b: Field, carry_in: Field) -> (Field, Field) {    // Intermediate sum (128-bit intermediate to detect overflow)
    
    let basic_sum_ab = add_with_carry_basic(a, b);
    let sum_ab = basic_sum_ab.0;
    let mut carry_out = basic_sum_ab.1;
    // Add the carry_in to the sum
    let carry_sum = add_with_carry_basic(sum_ab, carry_in);
    let sum = carry_sum.0;
    carry_out = carry_out + carry_sum.1;

    (sum, carry_out)
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


// Inputs: a, b are in the Field  borrow_in is in {0,1}
// Outputs: (chunk, borrow_out)
fn sub_with_borrow_field_chunk_size(a: Field, b: Field, borrow_in: Field) -> (Field, Field) {
    // Subtract two CHUNK_SIZE-bit integers with an incoming borrow bit
    let borrow_base = CARRY_BASE;
    let intermediate = a - b - borrow_in;

    // If intermediate < 0 (in Field arithmetic), we underflowed.
    // So we add back the base (2^CHUNK_SIZE), and set borrow_out = 1
    let borrow_out = if intermediate.lt(Field::from(0)) { Field::from(1) } else { Field::from(0) };
    let limb = if (borrow_out == Field::from(1)) {
        intermediate + borrow_base
    } else {
        intermediate
    };

    // Constraints explicitly (Noir-friendly)
    // assert((borrow_out * borrow_base + limb) == (a - b - borrow_in));
    // assert((borrow_out == Field::from(0))+(borrow_out == Field::from(1)));

    (limb, borrow_out)
}

// Subtract two 256-bit integers

fn sub_field256(a: FieldElement256, b: FieldElement256) -> (FieldElement256, Field) {
    let mut res = [Field::from(0);NUM_CHUNKS];
    let mut borrow = Field::from(0);

    for i in 0..NUM_CHUNKS {
        let out = sub_with_borrow_field_chunk_size(a.items[i], b.items[i], borrow);
        res[i] = out.0;
        borrow = out.1;
    }
    // At the end, borrow indicates if we underflowed the entire 256-bit number.
    // borrow = 0: a greater than eq to b
    // borrow = 1: a < b
    let res_field = FieldElement256 {
        items: res
    };
    (res_field, borrow)
}

fn sub_field512(a: FieldElement512, b: FieldElement512) -> (FieldElement512, Field) {
    let mut res = [Field::from(0);2 * NUM_CHUNKS];
    let mut borrow = Field::from(0);

    for i in 0..2 * NUM_CHUNKS {
        let out = sub_with_borrow_field_chunk_size(a.items[i], b.items[i], borrow);
        res[i] = out.0;
        borrow = out.1;
    }
    // At the end, borrow indicates if we underflowed the entire 256-bit number.
    // borrow = 0: a greater than eq to b
    // borrow = 1: a < b
    let res_field = FieldElement512 {
        items: res
    };
    (res_field, borrow)
}


fn add_mod_p(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
    let mut res = [Field::from(0); NUM_CHUNKS];
    let mut carry = Field::from(0);

    // Step 1: Explicit limb-wise addition with carry


    for i in 0..NUM_CHUNKS {
        let (sum_i, carry): (Field, Field) = add_with_carry(a.items[i], b.items[i], carry);
        res[i] = sum_i;
    }

    // // Now, explicitly, carry might be 0 or 1
    let res_field = FieldElement256 {
        items: res
    };

    // Step 2: Explicitly subtract modulus `p` to check if res greater than eq to p or if carry occurred
    let out = sub_field256(res_field, p);
    let res_minus_p = out.0;
    let borrow = out.1;

    // Step 3: Decide explicitly:
    // If carry == 1 (overflow), res is definitely greater than eq to p
    // OR if borrow == 0 (res greater than eq to p), then reduce explicitly by p.
    // Else, keep original res explicitly.
    // let reduce_flag = (Field::from(1) - borrow) + carry; 
    let reduce_flag = if is_greater_or_equal(res_field, p) {1} else {0};
    // reduce_flag greater than eq to 1 if carry==1 or no borrow (res greater than eq to p)

    // Convert reduce_flag explicitly to a boolean (0 or 1)
    
    assert((reduce_flag * (reduce_flag - 1)).eq(Field::from(0))); 

    let mut final_res = [Field::from(0); NUM_CHUNKS];
    for i in 0..NUM_CHUNKS{
        final_res[i] = res_minus_p.items[i] * reduce_flag + res[i] * (Field::from(1) - reduce_flag);
    }
    FieldElement256 {
        items: final_res
    }
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
    FieldElement256 {
        items: res
    }
}
// Negation of a 256-bit integer

// Multiply two 256-bit integers


fn mul_field32(a: Field, b: Field) -> (Field, Field) {
    let product: Field = a * b;
    let prod_u128: U128 = field_to_u128(product);
    
    // Use the unconstrained split function.
    let (lo_u128, hi_u128) = split_u128(prod_u128);
    
    let lo: Field = field_from_u128(lo_u128);
    let hi: Field = field_from_u128(hi_u128);
    
    assert( hi * CHUNK_MOD + lo == product );
    
    (lo, hi)
}



fn mul_limbs_8x8(a: FieldElement256, b: FieldElement256) -> FieldElement512 {
    let mut out = FieldElement512 {
        items: [Field::from(0); 2 * NUM_CHUNKS]
    };

    // Outer loops: multiply each limb from a and b.
    for i in 0..NUM_CHUNKS {
        for j in 0..NUM_CHUNKS {
            // Multiply a limb from a and b (32x32 = 64 bits).
            let (lo, hi) = mul_field32(a.items[i], b.items[j]);
            
            // Add the product into the appropriate positions in out.
            let (sum_lo, carry1) = add_with_carry(out.items[i + j], lo, Field::from(0));
            let (sum_hi, carry2) = add_with_carry(out.items[i + j + 1], hi, carry1);

            out.items[i + j] = sum_lo;
            out.items[i + j + 1] = sum_hi;

            // Now propagate any carry.
            let mut carry = carry2;
            // Fixed loop: run for exactly 2 * NUM_CHUNKS iterations.
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

    out
}

fn mul_limbs_9x9(a: FieldElement512Partial, b: FieldElement512Partial) -> FieldElement512 {
    let mut out = FieldElement512 {
        items: [Field::from(0); 2 * NUM_CHUNKS] // Or 17 limbs if needed
    };

    for i in 0..(NUM_CHUNKS + 1) {
        for j in 0..(NUM_CHUNKS + 1) {
            if i + j < (2 * NUM_CHUNKS - 1) {
            let (lo, hi): (Field, Field) = mul_field32(a.items[i], b.items[j]);

            let (sum_lo, carry1): (Field, Field) = add_with_carry(out.items[i + j], lo, Field::from(0));
            let (sum_hi, carry2): (Field, Field) =  add_with_carry(out.items[i + j + 1], hi, carry1);

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
    let current_bits: [u1; 32] = current.to_le_bits();
    let r_bits = current_bits[0];
    let r_field = if r_bits == 1 {
        Field::from(1)
    } else {
        Field::from(0)
    };
    let q_field = (current - r_field) / 2;
    (q_field, r_field)
}

fn div_by_two(a: FieldElement256) -> FieldElement256 {
    let mut result = FieldElement256 { items: [Field::from(0); NUM_CHUNKS] };
    let mut carry = Field::from(0);

    // Process limbs in descending order.
    for i in 0..NUM_CHUNKS {
        // Compute index in reverse order: highest limb first.
        let j = (NUM_CHUNKS - 1 - i);
        // current = (carry * BASE) + a.items[j]
        let current = carry * CARRY_BASE + a.items[j];
        // Use the helper to compute quotient q and remainder r when dividing current by 2.
        let (q, r) = div_by_two_helper(current);
        result.items[j] = q;
        carry = r;
    }

    result
}


// Let's just binary search for the quotient q and remainder r such that pq + r = x
unconstrained fn basic_reduce(x: FieldElement512) -> (FieldElement256, FieldElement256) {
    let mut high = p;
    let mut low = FieldElement256 {
        items: [Field::from(0); NUM_CHUNKS]
    };
    let mut mid = div_by_two(high);
    let mut q = FieldElement256 {
        items: [Field::from(0); NUM_CHUNKS]
    };
    let mut r = FieldElement256 {
        items: [Field::from(0); NUM_CHUNKS]
    };
    for i in 0..NUM_BITS {
        // If p * low <= x and low = high, then we can stop
        let prod_low = mul_limbs_8x8(low, p);
        let (mid_plus_one, _): (FieldElement256, Field) = add_256(mid, ONE_P);
        let prod_next = mul_limbs_8x8(mid_plus_one, p);
        
        if (is_greater_than_eq_512(x, prod_low) & is_greater_than_512(prod_next, x)) {
            // If (low + 1) * p > x >= p * low, then we can stop
            q = low;
            let out = sub_field512(x, prod_low);
            r = field512_to_256(out.0); 
        } else if is_greater_than_eq_512(x, prod_next) {
            // This is the case where we search the higher half 
            low = mid_plus_one;
            let out = add_256(mid, high);
            mid = div_by_two(out.0); 
        }
        else {
            // This is the case where we search the lower half
            high = mid;
            let out = add_256(low, mid);
            mid = div_by_two(out.0);
        }  
        
    }
    (q, r)
}





fn barrett_reduce(x: FieldElement512) -> FieldElement256 {
    // Step 1: Extract the top (NUM_CHUNKS+1) limbs from x.
    let mut x_high = FieldElement512Partial { 
        items: [Field::from(0); NUM_CHUNKS + 1] 
    };
    // We take limbs from index (NUM_CHUNKS - 1) up through the end.
    for i in 0..(NUM_CHUNKS + 1) {
        x_high.items[i] = x.items[i + NUM_CHUNKS - 1];
    };

    // Step 2: Compute q_full = x_high * mu using our fixed 9x9 multiplication.
    let q_full = mul_limbs_9x9(x_high, MU); // q_full is assumed to be a FieldElement512
    let mut q = FieldElement256 { 
        items: [Field::from(0); NUM_CHUNKS] 
    };
    // We take the upper NUM_CHUNKS limbs of q_full (i.e. indices NUM_CHUNKS..2*NUM_CHUNKS).
    for i in 0..NUM_CHUNKS {
        q.items[i] = q_full.items[i + NUM_CHUNKS];
    };

    // Step 3: Compute r = x - q * p.
    let qp = mul_limbs_8x8(q, p); // qp is a FieldElement512.
    let mut r = FieldElement512 { 
        items: [Field::from(0); 2 * NUM_CHUNKS] 
    };
    let mut borrow = Field::from(0);
    for i in 0..(2 * NUM_CHUNKS) {
        let (diff, new_borrow): (Field, Field) = sub_with_borrow_field_chunk_size(x.items[i], qp.items[i], borrow);
        r.items[i] = diff;
        borrow = new_borrow;
    };

    // Step 4: Let r_lo be the lower NUM_CHUNKS limbs of r.
    let mut r_lo = FieldElement256 { 
        items: [Field::from(0); NUM_CHUNKS] 
    };
    for i in 0..NUM_CHUNKS {
        r_lo.items[i] = r.items[i];
    };

    // Step 5: Conditionally subtract p once.
    let (r_minus_p, underflow): (FieldElement256, Field) = sub_field256(r_lo, p);
    let mut result = FieldElement256 { 
        items: [Field::from(0); NUM_CHUNKS] 
    };
    // underflow will be 0 if r_lo >= p (i.e. the subtraction worked without borrow),
    // so we choose r_minus_p; otherwise we choose r_lo.
    for i in 0..NUM_CHUNKS {
        result.items[i] = r_minus_p.items[i] * (Field::from(1) - underflow) + r_lo.items[i] * underflow;
    };

    result
}





fn mul_mod_p(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
    // Step 1: full 512-bit product
    let product = mul_limbs_8x8(a, b);
    if is_greater_than_512(p_512, product) {
        // If product is less than p, we can return it directly
        field512_to_256(product)
    }
    else {
        // let reduced = barrett_reduce(product);
        // Step 2: Simple reduction mod p
        let (q, r): (FieldElement256, FieldElement256) = basic_reduce(product);
        let out = add_512(mul_limbs_8x8(q, p), field256_to_512(r));
        assert(is_equal_512(out.0, product));
        
        r
    }
    
    
}

// Invert a 256-bit integer
unconstrained fn get_inv_mod_p(a: FieldElement256) -> FieldElement256 {
    let mut result = FieldElement256 {
        items: [Field::from(0); NUM_CHUNKS]
    };
    result.items[0] = Field::from(1);

    let mut base = a;
    
    for bit_index in 0..NUM_BITS {
        let limb_index = bit_index / CHUNK_SIZE;
        let bit_offset = bit_index % CHUNK_SIZE;
        // Extract the bit at bit_index from a
        let bit_mask = field_from_u128(shift_left_u128(U128::from_integer(1), bit_offset as u64));
        let is_one = (P_MINUS_2.items[limb_index].mul(bit_mask)) / bit_mask;

        let should_multiply = is_one;
        if should_multiply == Field::from(0) {
            break;
        }
        // result = (should_multiply == 1) ? result * base : result
        let res_mul = mul_mod_p(result, base);

        let mut new_result = FieldElement256 {
            items: [Field::from(0); NUM_CHUNKS]
        };
        for i in 0..NUM_CHUNKS {
            new_result.items[i] = res_mul.items[i] * should_multiply + result.items[i] * (Field::from(1) - should_multiply);
        }

        result = new_result;
        base = mul_mod_p(base, base);
    }

    result
}

fn inv_mod_p(a: FieldElement256) -> FieldElement256 {
    let a_inv = unsafe { get_inv_mod_p(a) };
    assert(is_equal(mul_mod_p(a, a_inv), ONE_P));
    a_inv
}

fn div_mod_p(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
    let b_inv = inv_mod_p(b);
    let res = mul_mod_p(a, b_inv);
    assert(is_equal(mul_mod_p(a, b), mul_mod_p(res, b)));
    res
}


// ------ Now that we have all the field items, 
// let's deal with the elliptic curve operations ------ //


struct ECPoint {
    x: FieldElement256,
    y: FieldElement256,
    infinity: bool,
}

// ------ Additional operations we might require for this field ------ // 
// Hash function over the above curve -- do we need this?
// Checking for map-to-curve constraints



// // #[field(bn254)]
fn main(m: Field) {
    print("m =");
    print(m);
    // let one: Field = 1;//Field::from(1);
    let one = Field::from(1);
    // let zero: Field = 0;//Field::from(0);
    let zero = Field::from(0);
    let minus_one = (zero - one);
    print("minus_one = ");  
    print(minus_one);
    assert(m == one);
}    


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
            Field::from(1), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    let b = FieldElement256 {
        items: [
            Field::from(1), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    assert(is_equal(a, b));
    assert(!is_equal(a, FieldElement256 {
        items: [
            Field::from(2), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    }));
}


#[test]
fn test_nonnative_simple_add() {
    let one = FieldElement256 {
        items: [
            Field::from(1), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    let three = FieldElement256 {
        items: [
            Field::from(3), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };
    let (sum, carry): (FieldElement256, Field) = add_256(one, two);
    assert(is_equal(sum, three));

}


#[test]
fn test_nonnative_sub() {
    let one = FieldElement256 {
        items: [
            Field::from(1), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    let three = FieldElement256 {
        items: [
            Field::from(3), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    
    let (diff, _): (FieldElement256, Field) = sub_field256(three, one);
    assert(is_equal(diff, two));

}

#[test]
fn test_nonnative_modular_add() {
    let one = FieldElement256 {
        items: [
            Field::from(1), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    let three = FieldElement256 {
        items: [
            Field::from(3), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
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
            Field::from(1), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };
    let two_512 = FieldElement512 {
        items: [
            Field::from(2), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    let prod: FieldElement512 = mul_limbs_8x8(one, two);

    assert(is_equal_512(prod, two_512));
}

#[test]
fn test_9x9_mul() {
    let one = FieldElement512Partial {
        items: [
            Field::from(1), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0),
        ],
    };

    let two = FieldElement512Partial {
        items: [
            Field::from(2), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0),
        ],
    };
    let two_512 = FieldElement512 {
        items: [
            Field::from(2), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };
    let prod: FieldElement512 = mul_limbs_9x9(one, two);
    assert(is_equal_512(prod, two_512));
}



#[test]
fn test_divide_by_two_helper() {
    let zero = Field::from(0);
    let one = Field::from(1);
    let two = Field::from(2);
    let three = Field::from(3);
    let four = Field::from(4);

    let (q, r) = div_by_two_helper(four);
    assert(q.eq(two));
    assert(r.eq(zero));

    let (q, r) = div_by_two_helper(three);
    assert(q.eq(one));
    assert(r.eq(one));

    let (q, r) = div_by_two_helper(one);
    assert(q.eq(zero));
    assert(r.eq(one));
}

#[test]
fn test_mul_mod_p() {
    let one = FieldElement256 {
        items: [
            Field::from(1), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };

    let two = FieldElement256 {
        items: [
            Field::from(2), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
            Field::from(0), Field::from(0),
        ],
    };
    
    

    let prod: FieldElement256 = mul_mod_p(one, two);
    
    assert(is_equal(prod, two));


    let (minus_one, _): (FieldElement256, Field) = sub_field256(p, one);
    let (minus_two, _): (FieldElement256, Field) = sub_field256(p, two);

    let prod: FieldElement256 = mul_mod_p(minus_one, minus_two);
    assert(is_equal(prod, two));
}