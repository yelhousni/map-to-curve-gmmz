// use std::time;
mod noir_poseidon_constants;
use ark_bn254::fr;
use ark_ec::bn::BnConfig;
use noir_poseidon_constants::{
    ARK_HEX,
    MDS_HEX,
    RF,
    RP,
    ALPHA,
    RATE,
    CAPACITY,
};
mod poseidon_bn254;
use poseidon_bn254::{
    poseidon_hash_2
};
mod utils;
use utils::{
    hex_to_fr
};
use std::str::FromStr;
use std::time::Instant;
use hex::FromHex;
use hex::ToHex;
use num_bigint::BigUint;
use num_traits::Num;  

use ark_ec::{twisted_edwards::Projective, AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, BigInteger256, Field, FpConfig, PrimeField};
use ark_bn254;
// use ark_bn254::{G1Projective as G, G1Affine as GAffine, Fr as ScalarField, Fq as BaseField};
use ark_grumpkin::{Projective as G, Affine as GAffine, Fr as ScalarField};
use ark_std::{Zero, UniformRand};
use ark_crypto_primitives::sponge::poseidon::{ 
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonDefaultConfigField, PoseidonSponge,
    grain_lfsr::PoseidonGrainLFSR
};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge, FieldBasedCryptographicSponge};
// use ark_crypto_primitives::crh::poseidon::CRH;
// use ark_crypto_primitives::crh::CRHScheme;
const CONST: i64 = -17;

pub trait FromScaler: CurveGroup where
{
    fn scaler_to_curve_elt(x: Self::BaseField) -> Option<Self::Affine>;
    fn map_to_curve_one_shot(x: Self::BaseField) -> Option<(Self::Affine, Self::BaseField)>;
    fn map_to_curve(x: Self::BaseField, t_max: u64) -> Option<(Self::Affine, Self::BaseField, Self::BaseField)>;
    fn poseidon_map_to_curve(inp_x: Self::BaseField, t_max: u64) -> Option<(Self::Affine, Self::BaseField, Self::BaseField)>;
    
}

fn bytes_to_fr(bytes: [u8; 32]) -> ark_bn254::Fr {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        for j in 0..8 {
            limbs[i] |= (bytes[8 * i + j] as u64) << (8 * j);
        }
    }
    let big_int = BigInt::new(limbs);
    ark_bn254::Fr::from_bigint(big_int).unwrap()
}





/// construct PoseidonConfig once
fn poseidon_bn254_t3_config() -> PoseidonConfig<ark_bn254::Fr> {
    let ark: Vec<Vec<ark_bn254::Fr>> = ARK_HEX.iter().map(|h| vec![hex_to_fr(h)]).collect();
    let mds: Vec<Vec<ark_bn254::Fr>> = MDS_HEX.iter().map(|h| vec![hex_to_fr(h)]).collect();
    PoseidonConfig::new(
        RF,
        RP,
        ALPHA,
        mds,
        ark,
        RATE,
        CAPACITY,
    )
}

/// Noir‑compatible hash_2
pub fn poseidon_hash_2_bn254(a: ark_bn254::Fr, b: ark_bn254::Fr) -> ark_bn254::Fr {
    poseidon_hash_2(a, b)
}




/// Convert an Fq to an 8-element array of 32-bit words (in little-endian order).
fn base_field_to_u32x8<F: PrimeField>(x: F) -> [u32; 8] {
    let mut out = [0u32; 8];
    let repr: F::BigInt = x.into_bigint();
    let limbs = repr.as_ref();
    for (i, &limb) in limbs.iter().enumerate() {
        out[2 * i]     = (limb & 0xffff_ffff) as u32;
        out[2 * i + 1] = (limb >> 32) as u32;
    }
    out
}

fn poseidon_custom_params<G: CurveGroup<BaseField: PrimeField>>(x: G::BaseField, t_max: u64, prime_bits: usize, security_level: usize) -> PoseidonConfig<G::BaseField>
where
    G::BaseField: Absorb,
    {
    let mut little_t = 0;
        // let big_t = Self::BaseField::from(t_max);


        // Define custom Poseidon parameters for the field
        //-----------------------------------------------
        // 1.  Choose your Poseidon permutation shape
        //-----------------------------------------------
        // let rate           = 2;   // absorb/squeeze 2 field elements per permutation
        // let capacity       = 6;   // arkworks fixes this for hash‑style sponges
        // let full_rounds: usize    = 8;   // see Poseidon paper Table 2
        // let partial_rounds: usize = 83;//57;  // see Poseidon paper Table 2
        // let alpha          = 5u64; // x^5 S‑box (coprime with p‑1 for BN254)

        let rate           = 2;   // absorb/squeeze 2 field elements per permutation
        let capacity       = 1;   // arkworks fixes this for hash‑style sponges
        let full_rounds: usize    = 8;   // see Poseidon paper Table 2
        let partial_rounds: usize = 57;  // see Poseidon paper Table 2
        let alpha          = 5u64; // x^5 S‑box (coprime with p‑1 for BN254)


        //-----------------------------------------------
        // 2.  Deterministically generate (ark, mds)
        //-----------------------------------------------
        let prime_bits   = G::BaseField::MODULUS_BIT_SIZE as u64;
        let skip_matrices = 0;    // normally leave at 0
        let mut lfsr = PoseidonGrainLFSR::new(
            false,
            prime_bits,
            (rate + capacity) as u64,
            full_rounds as u64,
            partial_rounds as u64,
        );

        let mut ark = Vec::<Vec<G::BaseField>>::with_capacity((full_rounds + partial_rounds) as usize);
        for _ in 0..(full_rounds + partial_rounds) {
            ark.push(lfsr.get_field_elements_rejection_sampling(rate + capacity));
        }

        let mut mds = Vec::<Vec<G::BaseField>>::with_capacity(rate + capacity);
        mds.resize(rate + capacity, vec![G::BaseField::zero(); rate + capacity]);
        for _ in 0..skip_matrices {
            let _ = lfsr.get_field_elements_mod_p::<G::BaseField>(2 * (rate + capacity));
        }

        // a qualifying matrix must satisfy the following requirements
        // - there is no duplication among the elements in x or y
        // - there is no i and j such that x[i] + y[j] = p
        // - the resultant MDS passes all the three tests

        let xs = lfsr.get_field_elements_mod_p::<G::BaseField>(rate + capacity);
        let ys = lfsr.get_field_elements_mod_p::<G::BaseField>(rate + capacity);

        for i in 0..(rate + capacity) {
            for j in 0..(rate + capacity) {
                mds[i][j] = (xs[i] + &ys[j]).inverse().unwrap();
            }
        }

        
        // //-----------------------------------------------
        // // 3.  Build a PoseidonConfig from those vectors
        // //-----------------------------------------------
        let params = PoseidonConfig::new(
            full_rounds,
            partial_rounds,
            alpha,
            mds,
            ark,
            rate,
            capacity,
        );

       
        params   
}

/// Convert eight 32-bit words (little-endian) back into an Fq.
/// Returns `None` if the 256-bit number is out of range for the field.
fn u32x8_to_base_field<F: PrimeField<BigInt = BigInt<4>>>(words: [u32; 8]) -> Option<F> {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let lo = words[2 * i] as u64;
        let hi = words[2 * i + 1] as u64;
        limbs[i] = lo | (hi << 32);
    }
    // let big_int = <F as PrimeField>::BigInt(limbs);
    let big_int = BigInt::new(limbs);
    F::from_bigint(big_int)
}

impl FromScaler for G {
    // where
    // // This is automatically satisfied because ark_bn254::Fr has the table
    // <Self as CurveGroup>::ScalarField: PoseidonDefaultConfigField,
    
    fn scaler_to_curve_elt(x: Self::BaseField) -> Option<Self::Affine> {
        let x_cube = x.square() * x;
        let y_sq = x_cube + Self::BaseField::from(CONST);
        let y = y_sq.sqrt();
        if y.is_none() {
            None
        }
        else {
            let x_base = x;
            let y_base = y.unwrap();
            let out = Self::Affine::new_unchecked(
                x_base.into(), 
                y_base.into()
            );
            Some(out)
        }
    }

    fn map_to_curve_one_shot(x: Self::BaseField) -> Option<(Self::Affine, Self::BaseField)> {
        let x_cube = x.square() * x;
        let y_sq = x_cube + Self::BaseField::from(CONST);
        let y = y_sq.sqrt();
        if y.is_none() {
            None
        }
        else {
            let x_base = x;
            let y_base = y.unwrap();
            let out = Self::Affine::new_unchecked(x_base, y_base);
            let z = y.unwrap().sqrt();
            if z.is_none() {
                return None;
            }
            Some((out, z.unwrap()))
        }   
    }

    fn map_to_curve(x: Self::BaseField, t_max: u64) -> Option<(Self::Affine, Self::BaseField, Self::BaseField)> {
        
        let mut little_t = 0;
        let big_t = Self::BaseField::from(t_max);

        while little_t < t_max {
            let field_t = Self::BaseField::from(little_t);
            let new_x = field_t + x*big_t;
            let x_cube = new_x.square() * new_x;
            let y_sq = x_cube + Self::BaseField::from(CONST);
            let y = y_sq.sqrt();
            

            if y.is_none() {
                little_t += 1;
            }
            else {
                let x_base = new_x;
                let y_base = y.unwrap();
                let out = Self::Affine::new_unchecked(x_base, y_base);
                let z = y.unwrap().sqrt();
                if z.is_some() {
                    return Some((out, z.unwrap(), field_t));
                }
                little_t += 1;
        }}
        None   
    }

    fn poseidon_map_to_curve(inp_x: Self::BaseField, t_max: u64) -> Option<(Self::Affine, Self::BaseField, Self::BaseField)> {
        let mut little_t = 0;
        let x = ark_bn254::Fr::from_bigint(inp_x.into_bigint()).unwrap();
        while little_t < t_max {
            let field_t = ark_bn254::Fr::from(little_t);
            let new_x = poseidon_hash_2(
                x,
                field_t,
            );
            let new_x_base = Self::BaseField::from_bigint(new_x.into_bigint()).unwrap();
            let x_cube = new_x_base.square() * new_x_base;
            let y_sq = x_cube + Self::BaseField::from(CONST);
            let y = y_sq.sqrt();
            
            if y.is_none() {
                little_t += 1;
            }
            else {
                let x_base = Self::BaseField::from_bigint(new_x.into_bigint()).unwrap();
                let y_base = Self::BaseField::from_bigint(y.unwrap().into_bigint()).unwrap();
                let out = Self::Affine::new_unchecked(x_base, y_base);
                let z = y_base.sqrt();
                if z.is_some() {
                    println!("out on curve = {:?}", out.is_on_curve());
                    let output_t = Self::BaseField::from_bigint(field_t.into_bigint()).unwrap();
                    return Some((out, z.unwrap(), output_t));
                }
                little_t += 1;
        }}
        None   
    }
        
}

fn str_to_bytearray(s: &str) -> Result<[u8; 32], String> {
    // 1. Detect the radix and strip prefixes
    let (radix, digits) = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (16, hex)
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) {
        (16, s)
    } else {
        // fall back to decimal
        (10, s)
    };

    let n = BigUint::from_str_radix(digits, radix)
        .map_err(|e| format!("cannot parse number: {e}"))?;

    // 3. Ensure it fits into 256 bits
    if n.bits() > 256 {
        return Err("value does not fit into 256 bits".into());
    }

    // 4. Convert to little‑endian bytes, pad to 32 bytes
    let mut bytes = n.to_bytes_le();
    bytes.resize(32, 0u8);           // 32 × 8 bits = 256 bits

    Ok(bytes.try_into().unwrap())
}

pub fn str_to_u32x8(s: &str) -> Result<[u32; 8], String> {
    // // 1. Detect the radix and strip prefixes
    // let (radix, digits) = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
    //     (16, hex)
    // } else if s.chars().all(|c| c.is_ascii_hexdigit()) {
    //     (16, s)
    // } else {
    //     // fall back to decimal
    //     (10, s)
    // };

    // let n = BigUint::from_str_radix(digits, radix)
    //     .map_err(|e| format!("cannot parse number: {e}"))?;

    // // 3. Ensure it fits into 256 bits
    // if n.bits() > 256 {
    //     return Err("value does not fit into 256 bits".into());
    // }

    // // 4. Convert to little‑endian bytes, pad to 32 bytes
    // let mut bytes = n.to_bytes_le();
    // bytes.resize(32, 0u8);           // 32 × 8 bits = 256 bits
    let bytes = str_to_bytearray(s)?;
    // 5. Chunk every 4 bytes → u32 word
    let mut out = [0u32; 8];
    for (i, chunk) in bytes.chunks(4).enumerate() {
        out[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    Ok(out)
}

fn str_to_4x8_bytearr(s: &str) -> Result<[[u8; 4]; 8], String> {
    let bytes = str_to_bytearray(s)?;
    // 5. Chunk every 4 bytes → u32 word
    let mut out = [[0u8; 4]; 8];
    for (i, chunk) in bytes.chunks(4).enumerate() {
        out[i] = chunk.try_into().unwrap();
    }
    Ok(out)
}

/// Convert an Fr to an 8-element array of 32-bit words (in little-endian order).
fn fr_to_u32x8(fe: &ScalarField) -> [u32; 8] {
    // Convert field element to its underlying 256-bit representation
    let repr: BigInteger256 = fe.into_bigint(); // repr.0 is [u64; 4]
    let limbs = repr.0;

    let mut out = [0u32; 8];
    // Each u64 limb splits into two u32 words
    for (i, &limb) in limbs.iter().enumerate() {
        out[2 * i]     = (limb & 0xffff_ffff) as u32;
        out[2 * i + 1] = (limb >> 32) as u32;
    }
    out
}

// fn bytes_to_fr(bytes: [u8; 32]) -> ScalarField {
//     let mut limbs = [0u64; 4];
//     for i in 0..4 {
//         for j in 0..8 {
//             limbs[i] |= (bytes[8 * i + j] as u64) << (8 * j);
//         }
//     }
//     let big_int = BigInt::new(limbs);
//     ScalarField::from_bigint(big_int).unwrap()
// }

/// Convert eight 32-bit words (little-endian) back into an Fr.
/// Returns `None` if the 256-bit number is out of range for the field.
fn u32x8_to_fr(words: [u32; 8]) -> Option<ScalarField> {
    let mut limbs = [0u64; 4];
    // Recombine pairs of 32-bit words into 64-bit limbs
    for i in 0..4 {
        let lo = words[2 * i] as u64;
        let hi = words[2 * i + 1] as u64;
        limbs[i] = lo | (hi << 32);
    }
    // Build the BigInteger256, then try to convert to Fr
    
    let big_int = BigInt::new(limbs);

    ScalarField::from_bigint(big_int)
}

/// Print the given BN254 field element as eight 32-bit hex words.
fn print_fr_hex_u32x8(fe: &ScalarField) {
    let words = fr_to_u32x8(fe);
    // For clarity, print each 32-bit limb on one line:
    // Field element as 8x u32 hex (little-endian): 
    println!("[");
    for w in words {
        println!("  0x{:08x},", w);
    }
    println!("]\n");
}

/// Print the given BN254 field element as eight 32-bit hex words.
fn print_fq_hex_u32x8<F: PrimeField>(fe: F) {
    let words = base_field_to_u32x8(fe);
    // For clarity, print each 32-bit limb on one line:
    // Field element as 8x u32 hex (little-endian): 
    print!("[");
    for w in words {
        print!("\"0x{:08x}\",", w);
    }
    print!("]\n");
}

/// convert any PrimeField element → 0x‑prefixed hex string
fn fr_to_hex<F: PrimeField>(f: F) -> String {
    // 1. field → limbs (little‑endian u64 array)
    let limbs_le = f.into_bigint().to_bytes_le();

    // 2. convert to big‑endian & drop leading zeros
    let mut be = limbs_le;
    be.reverse();                       // LE → BE
    while be.first() == Some(&0u8) {    // trim leading 0
        be.remove(0);
    }

    // 3. hex‑encode
    format!("0x{}", be.encode_hex::<String>())
}

fn print_native_witness<G: CurveGroup<BaseField: PrimeField>>(msg: G::BaseField, mapped_item: Option<(G::Affine, G::BaseField, G::BaseField)>) {
    println!("m = \"{:?}\"", msg);
    if mapped_item.is_some() {
        let item = mapped_item.unwrap();
        let x = item.0.x().unwrap();
        let y = item.0.y().unwrap();
        let z = item.1;
        let t = item.2;
        println!("x = \"{:?}\"", x);
        println!("y = \"{:?}\"", y);
        println!("z = \"{:?}\"", z);
        println!("t = \"{:?}\"", t);
        // println!("x = \"{:?}\"", fr_to_hex(x));
        // println!("y = \"{:?}\"", fr_to_hex(y));
        // println!("z = \"{:?}\"", fr_to_hex(z));
        // println!("t = \"{:?}\"", fr_to_hex(t));
    }
}

fn print_non_native_map_to_curve_witness<G: CurveGroup<BaseField: PrimeField>>(msg: G::BaseField, mapped_item: Option<(G::Affine, G::BaseField, G::BaseField)>) {
    
    if mapped_item.is_some() {
        let item = mapped_item.unwrap();
        let x = item.0.x().unwrap();
        let y = item.0.y().unwrap();
        let z = item.1;
        let t = item.2;
        println!("[m]");
        print!("items = ");
        print_fq_hex_u32x8(x);
        println!("[x]");
        print!("items = ");
        print_fq_hex_u32x8(x);
        println!("[y]");
        print!("items = ");
        print_fq_hex_u32x8(y);
        println!("[z]");
        print!("items = ");
        print_fq_hex_u32x8(z);
        println!("[t]");
        print!("items = ");
        print_fq_hex_u32x8(t);
    }
}

fn print_non_native_poseidon_witness<G: CurveGroup<BaseField: PrimeField>>(msg: G::BaseField, mapped_item: Option<(G::Affine, G::BaseField, G::BaseField)>) {
    
    if mapped_item.is_some() {
        let item = mapped_item.unwrap();
        let x = item.0.x().unwrap();
        let y = item.0.y().unwrap();
        let z = item.1;
        let t = item.2;
        println!("m = \"{:?}\"", msg);
        println!("nonce = \"{:?}\"", t);
        println!("[x]");
        print!("items = ");
        print_fq_hex_u32x8(x);
        println!("[y]");
        print!("items = ");
        print_fq_hex_u32x8(y);
        println!("[z]");
        print!("items = ");
        print_fq_hex_u32x8(z);
        
    }
}

fn main() {
    let start = Instant::now();
    let mut total = 0;
    for i in (1<<3)..((1<<3) + 1) {
        let x = <G as CurveGroup>::BaseField::from(i);
      
        let mapped_item = G::poseidon_map_to_curve(x, 256);
        // let mapped_item = G::map_to_curve(x, 256);
        println!("*****************************");
        print_native_witness::<G>(x, mapped_item);
        println!("*****************************");
        print_non_native_poseidon_witness::<G>(x, mapped_item);
        // println!("msg: {:?}", i);
        // println!("Multi try: {:?}", mapped_item);
        let curve_item = mapped_item.unwrap().0;
        let z_val = mapped_item.unwrap().1;
        let little_t = mapped_item.unwrap().2;
        // println!("Z square = {:?}", z_val.square());
        // println!("y_sq = {:?}", curve_item.y.square());
        // println!("x_cube + {:?} = {:?}", CONST, curve_item.x.square() * curve_item.x + <G as CurveGroup>::BaseField::from(CONST));
        
        
    
        // assert!(z_val.square() == curve_item.y.into());
        assert!(curve_item.is_on_curve());
        total += 1;
    }

    let duration = start.elapsed();
    println!("Time taken per search: {:?}", duration / total);

   
}

#[test]
fn test_u32x8fr_conversion() {
    // Test the conversion functions with a sample Fr element
    let scalar = 123456789u64;
    let fe = ScalarField::from(scalar);
    let words = fr_to_u32x8(&fe);
    let fe_converted = u32x8_to_fr(words).unwrap();
    let recovered_scalar = words[0] as u64 + ((words[1] as u64) << 32) as u64;
    // Check that the original and converted Fr elements are equal
    assert_eq!(fe, fe_converted);
    // Check that the original scalar and recovered scalar are equal
    assert_eq!(scalar, recovered_scalar);
}

#[test]
fn test_u32x8fq_conversion() {
    // Test the conversion functions with a sample Fr element
    let scalar = 123456789u64;
    let fe = <G as CurveGroup>::BaseField::from(scalar);
    let words = base_field_to_u32x8(fe);
    let fe_converted = u32x8_to_base_field(words).unwrap();
    let recovered_scalar = words[0] as u64 + ((words[1] as u64) << 32) as u64;
    // Check that the original and converted Fr elements are equal
    assert_eq!(fe, fe_converted);
    // Check that the original scalar and recovered scalar are equal
    assert_eq!(scalar, recovered_scalar);
}

#[test]
fn test_matches_noir() {
    let a = ark_bn254::Fr::from(1u64);
    let b = ark_bn254::Fr::from(1u64);
    let h = poseidon_hash_2_bn254(a, b);
    // reference value taken from Noir:
    //   poseidon_hash_2(Field(1), Field(1))
    let expected_str = "19042907124035163565171202924706009592412401364382052581183129985983909250676";
    let expected =
        ark_bn254::Fr::from_bigint(BigInt::from_str(expected_str).unwrap()).unwrap();
    assert_eq!(h, expected);
}