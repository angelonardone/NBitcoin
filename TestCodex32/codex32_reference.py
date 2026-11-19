# Independent check of the C# Codex32 output: the BIP-93 reference functions (ms32_polymod, checksums,
# ms32_decode, bech32_mul, bech32_lagrange, ms32_interpolate, ms32_recover), retyped from the BIP text.
# Usage: dotnet run -c Release -- cases CASES.json ; python -I codex32_reference.py CASES.json
import json, random, sys

MS32_CONST = 0x10ce0795c2fd1e62a
MS32_LONG_CONST = 0x43381e570bf4798ab26
MS32_HRP_EXPANDED_LENGTH = 5
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
MS32_VALID_LENGTHS = (48, 54, 61, 67, 74, 127)
BECH32_INV = [
    0, 1, 20, 24, 10, 8, 12, 29, 5, 11, 4, 9, 6, 28, 26, 31,
    22, 18, 17, 23, 2, 25, 16, 19, 3, 21, 14, 30, 13, 7, 27, 15,
]

def ms32_polymod(values):
    GEN = [0x19dc500ce73fde210, 0x1bfae00def77fe529, 0x1fbd920fffe7bee52, 0x1739640bdeee3fdad, 0x07729a039cfc75f5a]
    residue = 0x23181b3
    for v in values:
        b = (residue >> 60)
        residue = (residue & 0x0fffffffffffffff) << 5 ^ v
        for i in range(5):
            residue ^= GEN[i] if ((b >> i) & 1) else 0
    return residue

def ms32_long_polymod(values):
    GEN = [0x3d59d273535ea62d897, 0x7a9becb6361c6c51507, 0x543f9b7e6c38d8a2a0e, 0x0c577eaeccf1990d13c, 0x1887f74f8dc71b10651]
    residue = 0x23181b3
    for v in values:
        b = (residue >> 70)
        residue = (residue & 0x3fffffffffffffffff) << 5 ^ v
        for i in range(5):
            residue ^= GEN[i] if ((b >> i) & 1) else 0
    return residue

def ms32_verify_checksum(data):
    expanded_length = MS32_HRP_EXPANDED_LENGTH + len(data)
    if expanded_length >= 96:
        return expanded_length <= 1023 and ms32_long_polymod(data) == MS32_LONG_CONST
    return expanded_length <= 93 and ms32_polymod(data) == MS32_CONST

def ms32_decode(codex):
    if any(ord(x) < 33 or ord(x) > 126 for x in codex) or (codex.lower() != codex and codex.upper() != codex):
        return None
    codex = codex.lower()
    pos = codex.rfind("1")
    if pos < 2 or len(codex) not in MS32_VALID_LENGTHS:
        return None
    if not all(x in CHARSET for x in codex[pos+1:]):
        return None
    if codex[:pos] != "ms" or codex[pos+1].isalpha() or codex[pos+1] == "0" and codex[pos+6] != "s":
        return None
    data = [CHARSET.index(x) for x in codex[pos+1:]]
    if not ms32_verify_checksum(data):
        return None
    return data[:-13 if MS32_HRP_EXPANDED_LENGTH + len(data) < 94 else -15]

def bech32_mul(a, b):
    res = 0
    for i in range(5):
        res ^= a if ((b >> i) & 1) else 0
        a *= 2
        a ^= 41 if (32 <= a) else 0
    return res

def bech32_lagrange(l, x):
    n = 1
    c = []
    for i in l:
        n = bech32_mul(n, i ^ x)
        m = 1
        for j in l:
            m = bech32_mul(m, (x if i == j else i) ^ j)
        c.append(m)
    return [bech32_mul(n, BECH32_INV[i]) for i in c]

def ms32_interpolate(l, x):
    w = bech32_lagrange([s[5] for s in l], x)
    res = []
    for i in range(len(l[0])):
        n = 0
        for j in range(len(l)):
            n ^= bech32_mul(w[j], l[j][i])
        res.append(n)
    return res

def ms32_recover(shares):
    return ms32_interpolate(shares, 16)

def payload_to_seed(data, n):
    bits = ''.join(format(v, '05b') for v in data[6:])
    return bytes(int(bits[i:i+8], 2) for i in range(0, n * 8, 8))

# Self-check with BIP-93 test vector 2 before trusting this file.
_a = ms32_decode("MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM")
_c = ms32_decode("MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN")
assert payload_to_seed(ms32_recover([_a, _c]), 16).hex() == "d1808e096b35b209ca12132b264662a5"

cases = json.load(open(sys.argv[1]))
ok = 0
for c in cases:
    k = c['k']
    shares = [ms32_decode(s) for s in c['shares']]
    assert all(s is not None for s in shares), "the reference refused a C# share"
    for _ in range(3):
        secret = ms32_recover(random.sample(shares, k))
        assert CHARSET[secret[5]] == 's'
        assert payload_to_seed(secret, len(c['seed']) // 2).hex() == c['seed']
    if len(shares) > k:
        assert ms32_interpolate(shares[:k], shares[k][5]) == shares[k], "derived share differs"
    ok += 1
print(ok, "cases OK with the BIP-93 reference functions")
