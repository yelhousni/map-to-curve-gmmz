global T: Field = 256;
global CURVE_B: Field = Field::from(0) - Field::from(17);

fn check_map_to_curve_constraints(m: Field, x: Field, y: Field, z: Field, t: Field) -> bool {
    let cond_1 = (x == (t + m * T));
    let cond_2 = (y == (z * z));
    let x_sq = x * x;
    let f_x = (x_sq * x) + CURVE_B;
    let y_sq = y * y;
    let cond_3 = (y_sq == f_x);
    cond_1 & cond_2 & cond_3
}

fn main(m: Field, x: Field, y: Field, z: Field, t: Field) {
    assert(check_map_to_curve_constraints(m, x, y, z, t));
}

#[test]
fn test_main() {
    main(
        7,
        1792,
        2222603532014808061213222263845635574143735707039159930479525957984581958699,
        276759698173846535821495865193274967682377030871373817764620224677696820189,
        0,
    );
}

mod attacks;
