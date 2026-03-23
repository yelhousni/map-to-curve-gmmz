# Python simulation of Karatsuba 8x8 with 5x5 deferred carry and intermediate 'mid'

CHUNK_BITS = 32
NUM_CHUNKS = 8
BASE = 1 << CHUNK_BITS

def split4(a):
    """Split 8-chunk list into two 4-chunk halves."""
    half = NUM_CHUNKS // 2
    a_lo = a[:half]
    a_hi = a[half:NUM_CHUNKS]
    # Pad to length 5 for 5x5 operations
    a_lo += [0]
    a_hi += [0]
    return a_lo, a_hi

def add_chunks_5x5(a, b):
    """Add two 5-limb numbers (lists length 5), return 8-limb result (pad zeros)."""
    M2 = NUM_CHUNKS // 2 + 1  # 5
    res = [0] * NUM_CHUNKS
    carry = 0
    for i in range(M2):
        s = a[i] + b[i] + carry
        res[i] = s & (BASE - 1)
        carry = s >> CHUNK_BITS
    # carry goes into limb 5
    res[M2] = carry
    return res

def mul_chunks_5x5_deferred(a, b):
    """Multiply two 5-limb numbers, deferred carry, return 16-limb result."""
    M2 = NUM_CHUNKS // 2 + 1  # 5
    # Temporary out of size 16
    out = [0] * (2 * NUM_CHUNKS)
    # accumulate raw products
    for i in range(M2):
        for j in range(M2):
            prod = a[i] * b[j]
            lo = prod & (BASE - 1)
            hi = prod >> CHUNK_BITS
            out[i + j]     += lo
            out[i + j + 1] += hi
    # normalize all 16 limbs
    # accumulate into raw exactly as in Noir...
    print("PY raw5x5 a_lo×b_lo:")
    for i,v in enumerate(out):
        print(f"  [{i}] = 0x{v:08x}")

    carry = 0
    for k in range(2 * NUM_CHUNKS):
        s = out[k] + carry
        out[k] = s & (BASE - 1)
        carry = s >> CHUNK_BITS
    
    # normalize into norm...
    print("PY norm5x5 a_lo×b_lo:")
    for i,v in enumerate(out):
        print(f"  [{i}] = 0x{v:08x}")

    return out

def sub_chunks_16(a, b):
    """Subtract b from a for 16-limb arrays a,b."""
    res = [0] * (2 * NUM_CHUNKS)
    borrow = 0
    for i in range(2 * NUM_CHUNKS):
        diff = a[i] - b[i] - borrow
        if diff < 0:
            diff += BASE
            borrow = 1
        else:
            borrow = 0
        res[i] = diff
        # if i == 3 or i == 4:
        # print(f"Subtraction at index {i}: {hex(a[i])} - {hex(b[i])} = {hex(res[i])} with borrow {borrow}")
    return res, borrow

def karatsuba_with_mid(a, b):
    """Perform Karatsuba 8x8 on chunk arrays a,b, return full result and mid."""
    # split into 4+4, pad to 5
    a_lo, a_hi = split4(a)
    b_lo, b_hi = split4(b)
    print("a_lo:", [hex(x) for x in a_lo])
    print("a_hi:", [hex(x) for x in a_hi])
    print("b_lo:", [hex(x) for x in b_lo])
    print("b_hi:", [hex(x) for x in b_hi])
    # three 5x5 multiplies
    z0 = mul_chunks_5x5_deferred(a_lo, b_lo)
    z2 = mul_chunks_5x5_deferred(a_hi, b_hi)
    print("z0:", [hex(x) for x in z0])
    print("z2:", [hex(x) for x in z2])
    # half-sums
    sa = add_chunks_5x5(a_lo, a_hi)
    sb = add_chunks_5x5(b_lo, b_hi)
    z1 = mul_chunks_5x5_deferred(sa, sb)
    print("sa:", [hex(x) for x in sa])
    print("sb:", [hex(x) for x in sb])
    print("z1:", [hex(x) for x in z2])
    # mid = z1 - z0 - z2
    mid1, _ = sub_chunks_16(z1, z0)
    print("mid1:", [hex(x) for x in mid1])
    mid2, _ = sub_chunks_16(mid1, z2)
    print("mid2:", [hex(x) for x in mid2])
    # assemble
    half = NUM_CHUNKS // 2  # 4
    out = z0.copy()
    # add mid at shift half
    for i in range(len(mid2)):
        if i + half < len(out):
            out[i + half] += mid2[i]
    # add z2 at shift 2*half
    for i in range(len(z2)):
        if i + 2*half < len(out):
            out[i + 2*half] += z2[i]
    # final normalize
    carry = 0
    for k in range(2 * NUM_CHUNKS):
        s = out[k] + carry
        out[k] = s & (BASE - 1)
        carry = s >> CHUNK_BITS
    return out, mid2

def naive_mul_chunks_8x8(a, b):
    """Schoolbook multiply a,b 8-limb arrays -> normalized 16-limb."""
    out = [0] * (2 * NUM_CHUNKS)
    for i in range(NUM_CHUNKS):
        for j in range(NUM_CHUNKS):
            prod = a[i] * b[j]
            lo = prod & (BASE - 1)
            hi = prod >> CHUNK_BITS
            out[i + j]     += lo
            out[i + j + 1] += hi
    # normalize
    carry = 0
    for k in range(2 * NUM_CHUNKS):
        s = out[k] + carry
        out[k] = s & (BASE - 1)
        carry = s >> CHUNK_BITS
    return out

# Test input from user
a_chunks = [
    0xd87cfd46, 0x3c208c16, 0x6871ca8d, 0x97816a91,
    0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72
]
b_chunks = [
    0xd87cfd45, 0x3c208c16, 0x6871ca8d, 0x97816a91,
    0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72
]

# Run sim
karat_out, mid = karatsuba_with_mid(a_chunks, b_chunks)
schoolbook_out = naive_mul_chunks_8x8(a_chunks, b_chunks)

# Display results
print("mid (z1 - z0 - z2) limbs:", [hex(x) for x in mid])
print("Karatsuba result:", [hex(x) for x in karat_out])
print("Schoolbook  result:", [hex(x) for x in schoolbook_out])
print("Match:", karat_out == schoolbook_out)
