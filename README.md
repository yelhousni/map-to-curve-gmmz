# GMMZ Map-to-Curve Construction — Noir Implementation

This repository is a fork of https://github.com/Jasleen1/map-to-curve, the Noir/Barretenberg implementation accompanying:

> **J. Groth, H. Malvai, A. Miller, and Y.-N. Zhang**, *Constraint-Friendly Map-to-Elliptic-Curve-Group Relations and Their Applications*, Asiacrypt 2025.
> https://eprint.iacr.org/2025/1503

The paper proposes a constraint-efficient *map-to-elliptic-curve-group relation* that bypasses cryptographic hash functions. The construction is applied to two settings: **multiset hashing** for zkVM memory consistency (Section 5) and **BLS signature verification** in zkPoS protocols (Section 6).

This fork adds concrete exploit tests demonstrating vulnerabilities in the construction, identified and analysed in:

> **Y. El Housni and B. Bünz**, *On the Security of Constraint-Friendly Map-to-Curve Relations*, 2026.

The exploits break **BLS unforgeability** (producing valid signatures on fresh messages without the secret key), following ElHousni--Bünz. Addtionally, the original implementations missed a range check which breaks **injectivity** (enabling multiset hash collisions and zkVM memory forgery) and 

## Code and paper correspondence

### Map-to-curve relation (Section 4, Fig. 2)

The core relation R_M2G is implemented in `check_map_to_curve_constraints` (`native_noir_map_to_curve/src/main.nr`). A triple `(m, (x, y), (k, z))` belongs to the relation if:

1. `x = m * T + k` (x-increment embedding, `T = 256`)
2. `y = z^2` (canonical y-selection via quadratic residuosity)
3. `y^2 = x^3 - 17` (point lies on Grumpkin)

The paper proves injectivity and inverse exclusion when `k in [0, T)` and `q ≡ 3 (mod 4)` (Section 4.2). **However, the implementation does not enforce `k < T`.** The paper correctly states this condition but the circuit omits the range check, breaking injectivity (see Vulnerability 1 below).

### Nonnative field arithmetic (Section 7)

The nonnative branch (`noir_map_to_curve/`), which was merged into the `main` branch in this fork, reimplements the same relation using 256-bit limb arithmetic (`FieldElement256`) over BN254 Fr, with the field library in `non_native_field_ops/src/lib.nr`. This is used for benchmarking native vs. nonnative constraint costs (Section 7): ~31 constraints (native) vs. ~3M constraints (nonnative). The nonnative circuit (`check_nonnative_map_to_curve_constraints`) has the same vulnerabilities as the native one, plus an additional `mul_mod_p` non-canonical reduction issue (see Vulnerability 6).

### Concrete parameters (Sections 5.4 and 6.4)

The paper instantiates the construction with `T = 256`, message space `|M| <= 2^100` (zkVM) or `|M| <= 2^120` (BLS), on the Grumpkin curve (`y^2 = x^3 - 17` over BN254 Fr).

### Relationship to the attack paper

The BLS signature forgery (Vulnerabilities 3–5) corresponds to the automorphism-based attack described in ElHousni--Bünz. The missing `t < T` range check (Vulnerabilities 1–2) is a new finding specific to this implementation: the GMMZ paper correctly requires `k in [0, T)` in its formal definition (Fig. 2), but the Noir circuit never enforces this condition.

## Vulnerabilities

### 1. Missing `t < T` range check

The relation requires `k in [0, T)` for injectivity (Section 4.2, Fig. 2). The circuit checks `x == t + m * T` but never constrains `t < T`. A malicious prover sets `t >= T` to map two different messages to the same curve point.

**Consequence:** multiset hash collisions, zkVM memory forgery, BLS signature forgery.

### 2. `m = 0` universal collision

A special case of the above: with `m = 0`, the constraint becomes `x == t`, so any valid curve point can be claimed by message 0.

### 3. Order-3 automorphism on Grumpkin (j = 0)

Grumpkin is a j-invariant 0 curve with an order-3 automorphism:

```
phi(x, y) = (omega * x, y)
```

where `omega = 4407920970296243842393367215006156084916469457145843978461` is a primitive cube root of unity in BN254 Fr. Since `omega^3 = 1`, we have `(omega * x)^3 = x^3`, so `phi(P)` is on the curve whenever `P` is.

Starting from any valid witness `(m1, x1, y1, z1, t1)`, the forger computes `x2 = omega * x1` and decomposes it as `m2 * T + t2`. The witness `(m2, x2, y1, z1, t2)` passes all constraints.

**This attack does not require `t >= T`.** It is purely algebraic and works even with a proper range check. The EC-GGM security proof (Theorems 3 and 5) does not account for this because `phi` is a degree-1 endomorphism that acts on x-coordinates without querying the group oracle.

### 4. BLS signature forgery

Given a BLS signature `sigma1 = [sk] * P1` on message `m1` (Section 6, Fig. 5), the forger computes:

```
P2     = phi(P1)     = (omega * P1.x,     P1.y)
sigma2 = phi(sigma1) = (omega * sigma1.x,  sigma1.y)
```

Since `phi` commutes with scalar multiplication: `sigma2 = [sk] * P2`. The BLS verifier accepts `(m2, sigma2)` as valid. **Cost: 2 field multiplications on public data. No knowledge of `sk`.**

### 5. Lattice-based forgery with small messages

The automorphism induces the lattice `L = {(a, b) in Z^2 : b = omega * a mod q}`. The half-GCD on `(q, omega)` gives the shortest vector:

```
a = 147946756881789319000765030803803410728   (127 bits)
b = 9931322734385697763                        (64 bits)
```

Neither coordinate is on Grumpkin (both `a^3 - 17` and `b^3 - 17` are non-QR in Fr). By LLL-enumerating longer vectors `n1 * v1 + n2 * v2`, at `(n1 = -10000, n2 = 8)` we find a pair where both coordinates are on the curve with valid `z` witnesses:

```
x1 = 1183574055054314452692892902573449655824    (130 bits, m1 ~ 2^122)
x2 = 1479467568817893190107042985963766170492104  (141 bits, m2 ~ 2^133)
omega * x1 = x2 mod q
```

This works because `T` is not range-checked, so `M * T >> sqrt(q)`, giving enough lattice vectors for some to land on the curve. For comparison, on BN254 G1 (`y^2 = x^3 + 3`), the polynomial short vector from Proposition 1 of the paper lands directly on the curve (O(1) forgery, `m1 ~ 2^119`, `m2 ~ 2^56`, `T = 128`). That attack is verified by the SageMath script `bn254_forgery.sage`.

### 6. Nonnative-specific: `mul_mod_p` non-canonical reduction

The nonnative branch implements 256-bit field arithmetic using 8x32-bit limbs (Section 7). The `mul_mod_p` function uses an unconstrained hint (`unsafe { basic_reduce(product) }`) to obtain `(q, r)` and asserts `q * p + r == product`. However, `r` is **not constrained to be less than `p`**. A malicious prover can supply `r' = r + p`, `q' = q - 1` — the equality check still passes, but `r'` is non-canonical. Subsequent `is_equal` calls (which compare limbs chunk-by-chunk) return `false` for values that are equal mod `p`.

## Repository structure

```
native_noir_map_to_curve/
  src/main.nr        # original GMMZ circuit (Grumpkin, native field)
  src/attacks.nr      # exploit tests (6 attacks)

noir_map_to_curve/
  src/main.nr        # original GMMZ circuit (nonnative FieldElement256)
  src/attacks.nr      # exploit tests (6 attacks)

non_native_field_ops/
  src/lib.nr         # 256-bit field arithmetic library (Section 7)
```

## Running

```bash
nargo test --package native_noir_map_to_curve
nargo test --package noir_map_to_curve
```

Requires [Noir](https://noir-lang.org/) beta.19 or later.

## Compilation fixes

The original code does not compile on Noir beta.19. Minimal fixes applied:

- `bool * bool` → `bool & bool` (type error in beta.19)
- `U128` → `u128` (deprecated type)
- `dep::std::runtime::is_unconstrained` removed (unused)
- `[u1; 32]` → `[u1; 33]` in `div_by_two_helper` (carry overflow)
- Shift width type mismatches (`u8` → `u128`)
- Private imports removed (`is_equal_512`, `field256_to_512`, `mul_chunks_8x8`)
- `T` and `FieldElement256.items` made `pub`
