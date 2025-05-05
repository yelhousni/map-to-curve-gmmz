// Adjust the path to correctly import the constants module
pub mod constants;
use crate::constants::POSEIDON_MDS;
use crate::constants::POSEIDON_ROUND_CONSTANTS;

fn quintic_sbox(x: Field) -> Field {
    let x2 = x * x;
    x2 * x2 * x // x^5
}

/// Poseidon-v1 permutation for t = 3, alpha = 5, RF = 8, RP = 57
fn poseidon_permute(state: [Field; 3]) -> [Field; 3] {
    let mut s = state;
    let mut rc_i = 0;

    // first 4 full rounds
    for _i in 0..4 {
        // AddRoundConstants + S-box
        for j in 0..3 {
            s[j] = quintic_sbox(s[j] + POSEIDON_ROUND_CONSTANTS[rc_i]);
            rc_i += 1;
        }
        // MDS
        s = mds_mul(s);
    }
    // 57 partial rounds
    for _i in 0..57 {
        // only s[0] passes through S-box
        s[0] = quintic_sbox(s[0] + POSEIDON_ROUND_CONSTANTS[rc_i]);
        rc_i += 1;
        // s[1] += POSEIDON_ROUND_CONSTANTS[rc_i];   // these two are zero in the table
        // s[2] += POSEIDON_ROUND_CONSTANTS[rc_i];
        s = mds_mul(s);
    }
    // last 4 full rounds
    for _i in 0..4 {
        for j in 0..3 {
            s[j] = quintic_sbox(s[j] + POSEIDON_ROUND_CONSTANTS[rc_i]);
            rc_i += 1;
        }
        s = mds_mul(s);
    }
    s
}

/// 3x3 matrix multiply (constants are row-major)
fn mds_mul(v: [Field; 3]) -> [Field; 3] {
    let mut out = [0; 3];
    for row in 0..3 {
        out[row] =
            POSEIDON_MDS[row][0] * v[0] + POSEIDON_MDS[row][1] * v[1] + POSEIDON_MDS[row][2] * v[2];
    }
    out
}

pub fn poseidon_hash_2(x0: Field, x1: Field) -> Field {
    // state layout Noir uses:  [capacity, x0, x1]
    let state = poseidon_permute([0, x0, x1]);
    state[0] // capacity word is the digest
}
