# constants_to_rust_array.py
from pathlib import Path

# 1️⃣  read "0x…, 0x…, 0x…"  (ignores whitespace and trailing commas)
raw = Path("src/ark_constants").read_text()
items = [tok.strip() for tok in raw.split(",") if tok.strip()]

# 2️⃣  print a Rust array literal
print("const ARK_HEX: [&str; {}] = [".format(len(items)))
for tok in items:
    print(f'    "{tok}",')
print("];")