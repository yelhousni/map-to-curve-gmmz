// use std::time;
use std::time::Instant;

use ark_ec::{twisted_edwards::Projective, AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger256, Field, FpConfig, PrimeField};
use ark_bn254::{G1Projective as G, G1Affine as GAffine, Fr as ScalarField};
// use ark_grumpkin::{Projective as G, Affine as GAffine, Fr as ScalarField};
use ark_std::{Zero, UniformRand};

const CONST: i64 = 3;//-17;

pub trait FromScaler: CurveGroup {
    fn scaler_to_curve_elt(x: Self::BaseField) -> Option<Self::Affine>;
    fn map_to_curve_one_shot(x: Self::BaseField) -> Option<(Self::Affine, Self::BaseField)>;
    fn map_to_curve(x: Self::BaseField, t_max: u64) -> Option<(Self::Affine, Self::BaseField, Self::BaseField)>;
    
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
            let out = Self::Affine::new_unchecked(x_base, y_base);
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
    println!("]");
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
    print!("]");
}

fn main() {
    
    let start = Instant::now();
    let mut total = 0;
    for i in (1<<3)..(1<<3 + 1) {
        let x = <G as CurveGroup>::BaseField::from(i);
      
        let mapped_item = G::map_to_curve(x, 256);
        println!("msg: {:?}", i);
        println!("Multi try: {:?}", mapped_item);
        let curve_item = mapped_item.unwrap().0;
        let z_val = mapped_item.unwrap().1;
        let little_t = mapped_item.unwrap().2;
        println!("Z square = {:?}", z_val.square());
        println!("y_sq = {:?}", curve_item.y.square());
        println!("x_cube + {:?} = {:?}", CONST, curve_item.x.square() * curve_item.x + <G as CurveGroup>::BaseField::from(CONST));
        
        
        assert!(z_val.square() == curve_item.y);
        assert!(curve_item.is_on_curve());

        print!("[m]\n");
        print!("items = ");
        print_fq_hex_u32x8(x);
        print!("\n");
        print!("[x]\n");
        print!("items = ");
        print_fq_hex_u32x8(curve_item.x);
        print!("\n");
        print!("[y]\n");
        print!("items = ");
        print_fq_hex_u32x8(curve_item.y);
        print!("\n");
        print!("[z]\n");
        print!("items = ");
        print_fq_hex_u32x8(z_val);
        print!("\n");
        print!("[t]\n");
        print!("items = ");
        print_fq_hex_u32x8(little_t);

        total += 1;
    }

    let duration = start.elapsed();
    // println!("Time taken per search: {:?}", duration / total);

   
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