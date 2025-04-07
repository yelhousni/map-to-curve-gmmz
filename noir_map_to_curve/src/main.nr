use dep::std::field::bn254;
use dep::std::hash::poseidon;
use dep::std::hash::blake2s;
use dep::std::hash::blake3;
use dep::std::hash::pedersen_hash;
global T: Field = 256;


// ----- Here we deal with field representation and 
// arithmetic for a field that is larger than the native field ---- //
global NUM_CHUNKS = 8;
global CHUNK_SIZE = 32;
global NUM_BITS = 256;
global CHUNK_MOD = Field::from(1 << CHUNK_SIZE);


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

// Note that we need to use 32-bit chunks for the field elements,
// when using a "64-bit" native field, such as Goldilocks,
// since the underlying field is usually less than 64 bits in reality,
// and working with 64-bit chunks could cause overflow.
global p = FieldElement256 { 
    items: [
        Field::from(0xd87cfd47), Field::from(0x3c208c16), // limb0 (low, high)
        Field::from(0x6871ca8d), Field::from(0x97816a91), // limb1
        Field::from(0x8181585d), Field::from(0xb85045b6), // limb2
        Field::from(0xe131a029), Field::from(0x30644e72), // limb3
    ],
};

global MU: FieldElement512Partial = FieldElement512Partial {
    items : [
        Field::from(0x992d43c9), Field::from(0x53a5b7d7),
        Field::from(0x4c1bf7d7), Field::from(0xe5fa6a9d),
        Field::from(0x18c6cac0), Field::from(0xb21768f2),
        Field::from(0xc7fffaa0), Field::from(0x30f19549),
        Field::from(0x00000003)
    ],
};


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

fn add_with_carry_basic(a: Field, b: Field) -> (Field, Field) {
    // Add two CHUNK_SIZE-bit integers with an incoming carry bit
    // Input:
    //   a, b: Field elements to be added
    // Output:
    //   (sum: Field, carry_out: Field)
    
    let sum_ab = a + b;
    let carry_out = sum_ab / Field::from(1 << CHUNK_SIZE);
    // If the sum is greater than 2^CHUNK_SIZE - 1, we have an overflow
    // and need to set the carry_out to 1

    let chunk: Field = sum_ab - carry_out * Field::from(1 << CHUNK_SIZE);
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



// Inputs: a, b are in the Field  borrow_in is in {0,1}
// Outputs: (chunk, borrow_out)
fn sub_with_borrow_field_chunk_size(a: Field, b: Field, borrow_in: Field) -> (Field, Field) {
    // Subtract two CHUNK_SIZE-bit integers with an incoming borrow bit
    let borrow_base = Field::from(1 << CHUNK_SIZE);
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


// fn add_mod_p(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
//     let mut res = [Field::from(0); NUM_CHUNKS];
//     let mut carry = Field::from(0);

//     for i in 0..NUM_CHUNKS {
//         let out = add_with_carry(a.items[i], b.items[i], carry);
//         res[i] = out.0;
//         carry = out.1;
//     }
//     let mut res_field = FieldElement256 {
//         items: res
//     };

//     // Conditional reduction
//     if is_greater_or_equal(res_field, p) {
//         let out = sub_field256(res_field, p);
//         res_field = out.0;
//         carry = out.1;
//     }
//     res_field
    
// }

fn add_mod_p(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
    let mut res = [Field::from(0); NUM_CHUNKS];
    let mut carry = Field::from(0);

    // Step 1: Explicit limb-wise addition with carry
    for i in 0..NUM_CHUNKS {
        let out = add_with_carry(a.items[i], b.items[i], carry);
        res[i] = out.0;
        carry = out.1;
    }
    // Now, explicitly, carry might be 0 or 1

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
    let reduce_flag = (Field::from(1) - borrow) + carry; 
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
    let product = a * b;

          
    let hi = product / CHUNK_MOD;
    let lo = product - hi * CHUNK_MOD; 
    // Note that hi * CHUNK_MOD + lo == product

    (lo, hi)
}

fn mul_limbs_8x8(a: FieldElement256, b: FieldElement256) -> FieldElement512 {
    let mut out = FieldElement512 {
        items: [Field::from(0); 2 * NUM_CHUNKS]
    };

    for i in 0..NUM_CHUNKS {
        for j in 0..NUM_CHUNKS {
            let (lo, hi): (Field, Field) = mul_field32(a.items[i], b.items[j]);

            let (sum_lo, carry1): (Field, Field) = add_with_carry(out.items[i + j], lo, Field::from(0));
            let (sum_hi, carry2): (Field, Field) = add_with_carry(out.items[i + j + 1], hi, carry1);

            out.items[i + j] = sum_lo;
            out.items[i + j + 1] = sum_hi;

            let mut carry = carry2;
            for offset in 0..(NUM_CHUNKS + 1) {
                let k = i + j + 2 + offset;
                let do_update = if carry != Field::from(0) { Field::from(1) } else { Field::from(0) };

                let (sum, new_carry): (Field, Field) = add_with_carry(out.items[k], Field::from(0), carry);
                out.items[k] = sum * do_update + out.items[k] * (Field::from(1) - do_update);
                carry = new_carry * do_update + carry * (Field::from(1) - do_update);
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
            let (lo, hi): (Field, Field) = mul_field32(a.items[i], b.items[j]);

            let (sum_lo, carry1): (Field, Field) = add_with_carry(out.items[i + j], lo, Field::from(0));
            let (sum_hi, carry2): (Field, Field) =  add_with_carry(out.items[i + j + 1], hi, carry1);

            out.items[i + j] = sum_lo;
            out.items[i + j + 1] = sum_hi;

            let mut carry = carry2;
            for offset in 0..(NUM_CHUNKS + 1) {
                let k = i + j + 2 + offset;
                let do_update = if carry != Field::from(0) { Field::from(1) } else { Field::from(0) };

                let (sum, new_carry): (Field, Field)= add_with_carry(out.items[k], Field::from(0), carry);
                out.items[k] = sum * do_update + out.items[k] * (Field::from(1) - do_update);
                carry = new_carry * do_update + carry * (Field::from(1) - do_update);
            }
        }
    }

    out
}


fn barrett_reduce(x: FieldElement512) -> FieldElement256 {
    // Step 1: Extract top NUM_CHUNKS + 1 limbs from x
    let mut x_high = FieldElement512Partial {
        items: [Field::from(0); NUM_CHUNKS + 1]
    };

    for i in 0..(NUM_CHUNKS + 1) {
        x_high.items[i] = x.items[i + NUM_CHUNKS - 1];
    }

    // Step 2: q = floor(x_high * MU / 2^512)
    let q_full = mul_limbs_9x9(x_high, MU); // Output: FieldElement512
    let mut q = FieldElement256 {
        items: [Field::from(0); NUM_CHUNKS]
    };

    for i in 0..NUM_CHUNKS {
        q.items[i] = q_full.items[i + NUM_CHUNKS];
    }

    // Step 3: r = x - q * p
    let qp = mul_limbs_8x8(q, p); // Output: FieldElement512
    let mut r = FieldElement512 {
        items: [Field::from(0); 2 * NUM_CHUNKS]
    };

    let mut borrow = Field::from(0);
    for i in 0..(2 * NUM_CHUNKS) {
        let out = sub_with_borrow_field_chunk_size(x.items[i], qp.items[i], borrow);
        r.items[i] = out.0;
        borrow = out.1;
    }

    // Step 4: Conditionally subtract p again if r_lo \geq p
    let mut r_lo = FieldElement256 {
        items: [Field::from(0); NUM_CHUNKS]
    };

    for i in 0..NUM_CHUNKS {
        r_lo.items[i] = r.items[i];
    }

    let out = sub_field256(r_lo, p);
    let r_minus_p = out.0;
    let underflow = out.1;
    // Step 5: r = r - p if underflow == 1 and 
    // r = r + p if underflow == 0

    let mut result = FieldElement256 {
        items: [Field::from(0); NUM_CHUNKS]
    };

    for i in 0..NUM_CHUNKS {
        result.items[i] =
            r_minus_p.items[i] * (Field::from(1) - underflow) +
            r_lo.items[i] * underflow;
    }

    result
}


fn mul_mod_p(a: FieldElement256, b: FieldElement256) -> FieldElement256 {
    // Step 1: full 512-bit product
    let product = mul_limbs_8x8(a, b);

    // Step 2: Barrett reduction mod p
    let reduced = barrett_reduce(product);

    reduced
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
        let bit_mask = Field::from(1 << bit_offset);
        let is_one = (P_MINUS_2.items[limb_index].mul(bit_mask)) / Field::from(1 << bit_offset);

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
