use non_native_field_ops::{
    add_mod_p, curve_B, field256_to_512, field_elt_to_native, is_equal, is_equal_512,
    mul_chunks_8x8, mul_mod_p, T,
};
use non_native_field_ops::FieldElement256;

/// Checking for map-to-curve constraints
pub fn check_nonnative_map_to_curve_constraints(
    m: Field,
    x: FieldElement256,
    y: FieldElement256,
    z: FieldElement256,
    t: Field,
) -> bool {
    // Here we are checking that (x == (t + m * T));
    // let m_times_t = mul_mod_p(m, NON_NATIVE_T);
    // let t_plus_m_times_t = add_mod_p(t, m_times_t);
    let m_times_t = m * T;
    let t_plus_m_times_t = t + m_times_t;
    let x_native = field_elt_to_native(x);
    let cond_1 = (x_native == t_plus_m_times_t);
    let z_sq = mul_mod_p(z, z);
    let cond_2 = is_equal(y, z_sq);
    let x_sq = mul_mod_p(x, x);
    
    let f_x = add_mod_p(mul_mod_p(x_sq, x), curve_B());

    let y_sq = mul_mod_p(y, y);

    let cond_3 = is_equal(y_sq, f_x);


 

    cond_1 * cond_2 * cond_3
}

// // #[field(bn254)]
fn main(m: Field, x: FieldElement256, y: FieldElement256, z: FieldElement256, nonce: Field) {
    let check = check_nonnative_map_to_curve_constraints(m, x, y, z, nonce);
    assert(check);
}
