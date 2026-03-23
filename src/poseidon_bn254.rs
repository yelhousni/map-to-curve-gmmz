use ark_bn254::Fr;
use ark_ff::{BigInteger256, PrimeField, Field};
use hex::FromHex;
use crate::noir_poseidon_constants::{
    ARK_HEX,
    MDS_HEX,
    RF,
    RP,
    ALPHA,
    RATE,
    CAPACITY,
};
use crate::utils::hex_to_fr;

/// ------------------------------------------------------------------
/// MDS as a 3×3 array
/// ------------------------------------------------------------------
fn mds() -> [[ark_bn254::Fr; 3]; 3] {
    let mut out = [[ark_bn254::Fr::from(0u64); 3]; 3];
    let mut it = MDS_HEX.iter().map(|h| hex_to_fr(h));
    for r in 0..3 {
        for c in 0..3 {
            out[r][c] = it.next().unwrap();
        }
    }
    out
}

/// Matrix mul
fn mds_mul(v: [Fr; 3], m: &[[Fr; 3]; 3]) -> [ark_bn254::Fr; 3] {
    [
        m[0][0] * v[0] + m[0][1] * v[1] + m[0][2] * v[2],
        m[1][0] * v[0] + m[1][1] * v[1] + m[1][2] * v[2],
        m[2][0] * v[0] + m[2][1] * v[1] + m[2][2] * v[2],
    ]
}

/// x ↦ x⁵ over the field
#[inline(always)]
fn quintic(x: ark_bn254::Fr) -> ark_bn254::Fr { x.square().square() * x }

/// ------------------------------------------------------------------
/// 4)  Expand sparse RC → dense [65][3]  (non‑zero lives in column 0)
/// ------------------------------------------------------------------
fn dense_rc() -> [[ark_bn254::Fr; 3]; 65] {
    let mut it = ARK_HEX.iter().map(|h| hex_to_fr(h));
    let mut ark = [[ark_bn254::Fr::from(0u64); 3]; 65];

    // first 4 full rounds
    for r in 0..4 {
        ark[r] = [it.next().unwrap(), it.next().unwrap(), it.next().unwrap()];
    }
    // 57 partial rounds
    for r in 4..61 {
        ark[r] = [it.next().unwrap(), ark_bn254::Fr::from(0u64), ark_bn254::Fr::from(0u64)];
    }
    // last 4 full rounds
    for r in 61..65 {
        ark[r] = [it.next().unwrap(), it.next().unwrap(), it.next().unwrap()];
    }
    ark
}



/// ------------------------------------------------------------------
/// 5)  Public hash₂:  (0, a, b) ▸ Poseidon ▸ state[0]
/// ------------------------------------------------------------------
pub fn poseidon_hash_2(a: ark_bn254::Fr, b: ark_bn254::Fr) -> ark_bn254::Fr {
    let mut state = [ark_bn254::Fr::from(0u64), a, b];
    let ark = dense_rc();
    let mds = mds();

    // 65 rounds total 



    for r in 0..65 {
        // add round constants
        for i in 0..3 {
            state[i] += ark[r][i];

        }
        // S‑box layer
        if r < 4 || r >= 61 {                     // full rounds
            for i in 0..3 { state[i] = quintic(state[i]); }
        } else {                                  // partial rounds
            state[0] = quintic(state[0]);
        }
        // MDS
        state = mds_mul(state, &mds);
    }
    state[0]
}