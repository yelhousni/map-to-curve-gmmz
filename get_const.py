import re

# The input string
s = """
items : [
        Field::from(0x992d43c9), Field::from(0x53a5b7d7),
        Field::from(0x4c1bf7d7), Field::from(0xe5fa6a9d),
        Field::from(0x18c6cac0), Field::from(0xb21768f2),
        Field::from(0xc7fffaa0), Field::from(0x30f19549),
        Field::from(0x00000003)
    ]
"""

# Use regex to find all hex numbers in the form Field::from(0x...)
pattern = r"Field::from\(\s*0x([0-9a-fA-F]+)\s*\)"
matches = re.findall(pattern, s)

byte_arrays = []
for hex_str in matches:
    # Convert the hex string to an integer.
    value = int(hex_str, 16)
    # Convert the integer to an 8-byte little-endian bytes object.
    b = value.to_bytes(4, byteorder="little")
    # Convert bytes to a list of integers (each 0-255) to mimic [u8; 8]
    byte_array = list(b)
    byte_arrays.append(byte_array)

# Print the resulting array of byte arrays.
for arr in byte_arrays:
    print(f"{arr},")