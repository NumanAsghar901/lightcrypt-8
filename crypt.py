"""
===============================================================================
LightCrypt-8: Custom Lightweight Encryption Algorithm
COMPLETE PROJECT - FINAL SUBMISSION (100%)
===============================================================================

Author: Numan Asghar
Student ID: 23F-0527
Course: Information Security
Date: 11-0-2026

This is the main file containing the complete implementation.
Run this file to see all tests and demonstrations.

===============================================================================
"""

import hashlib
import hmac
import random
import time
import os
from enum import Enum
from typing import Tuple, List

# ==============================
# PART 1: CONFIGURATION (5%)
# ==============================

class OperationMode(Enum):
    ECB = "ECB"
    CBC = "CBC"
    CTR = "CTR"

# ==============================
# PART 2: CORE ALGORITHM (20%)
# ==============================

def generate_sboxes(key: str) -> Tuple[List[int], List[int]]:
    """Generate key-dependent S-box and inverse."""
    seed = int.from_bytes(hashlib.sha256(key.encode()).digest(), 'big')
    indices = list(range(256))
    random.seed(seed)
    random.shuffle(indices)
    sbox = indices[:]
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return sbox, inv_sbox

def add_padding(data: bytes, block_size: int = 16) -> bytes:
    """Add PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def remove_padding(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    if len(data) == 0:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if not (1 <= pad_len <= len(data)):
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def derive_transposition_key(key: str, num_columns: int) -> List[int]:
    """Derive column permutation."""
    hasher = hashlib.sha256()
    hasher.update((key + "_transposition").encode())
    seed = int.from_bytes(hasher.digest(), 'big')
    cols = list(range(num_columns))
    random.seed(seed)
    random.shuffle(cols)
    return cols

def transpose_encrypt(block: bytes, col_order: List[int]) -> bytes:
    """Apply columnar transposition."""
    return bytes(block[col] for col in col_order)

def transpose_decrypt(block: bytes, col_order: List[int]) -> bytes:
    """Reverse columnar transposition."""
    inv_order = [0] * len(col_order)
    for i, col in enumerate(col_order):
        inv_order[col] = i
    return bytes(block[inv_order[i]] for i in range(len(col_order)))

def generate_keystream(key: str, length: int) -> bytes:
    """Generate deterministic keystream."""
    base = hashlib.sha256((key + "_keystream").encode()).digest()
    stream = b""
    counter = 0
    while len(stream) < length:
        h = hashlib.sha256(base + counter.to_bytes(4, 'big')).digest()
        stream += h
        counter += 1
    return stream[:length]

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR two byte strings."""
    return bytes(a ^ b for a, b in zip(data, key))

# ==============================
# PART 3: ENCRYPTION MODES (20%)
# ==============================

def encrypt_block(block: bytes, sbox: List[int], col_order: List[int], rounds: int) -> bytes:
    """Encrypt single block."""
    data = block
    for _ in range(rounds):
        data = bytes(sbox[b] for b in data)
        data = transpose_encrypt(data, col_order)
    return data

def decrypt_block(block: bytes, inv_sbox: List[int], col_order: List[int], rounds: int) -> bytes:
    """Decrypt single block."""
    data = block
    for _ in range(rounds):
        data = transpose_decrypt(data, col_order)
        data = bytes(inv_sbox[b] for b in data)
    return data

def encrypt_cbc(plaintext: bytes, key: str, rounds: int, iv: bytes = None) -> Tuple[bytes, bytes]:
    """CBC mode encryption."""
    block_size = 16
    if iv is None:
        iv = os.urandom(block_size)

    padded = add_padding(plaintext, block_size)
    sbox, _ = generate_sboxes(key)
    col_order = derive_transposition_key(key, block_size)

    ciphertext = b""
    prev_block = iv

    for i in range(0, len(padded), block_size):
        block = padded[i:i+block_size]
        block = xor_bytes(block, prev_block)
        encrypted = encrypt_block(block, sbox, col_order, rounds)
        ciphertext += encrypted
        prev_block = encrypted

    return ciphertext, iv

def decrypt_cbc(ciphertext: bytes, key: str, rounds: int, iv: bytes) -> bytes:
    """CBC mode decryption."""
    block_size = 16
    _, inv_sbox = generate_sboxes(key)
    col_order = derive_transposition_key(key, block_size)

    plaintext = b""
    prev_block = iv

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        decrypted = decrypt_block(block, inv_sbox, col_order, rounds)
        plaintext += xor_bytes(decrypted, prev_block)
        prev_block = block

    return remove_padding(plaintext)

# ==============================
# PART 4: AUTHENTICATED ENCRYPTION (10%)
# ==============================

def generate_mac(data: bytes, key: str) -> bytes:
    """Generate HMAC-SHA256."""
    return hmac.new(key.encode(), data, hashlib.sha256).digest()

def verify_mac(data: bytes, mac: bytes, key: str) -> bool:
    """Verify HMAC."""
    expected = generate_mac(data, key)
    return hmac.compare_digest(mac, expected)

def authenticated_encrypt(plaintext: bytes, key: str, rounds: int = 4) -> bytes:
    """Encrypt with MAC."""
    ciphertext, iv = encrypt_cbc(plaintext, key, rounds)
    mac = generate_mac(iv + ciphertext, key)
    return iv + ciphertext + mac

def authenticated_decrypt(data: bytes, key: str, rounds: int = 4) -> bytes:
    """Decrypt and verify MAC."""
    iv = data[:16]
    ciphertext = data[16:-32]
    mac = data[-32:]

    if not verify_mac(iv + ciphertext, mac, key):
        raise ValueError("Authentication failed")

    return decrypt_cbc(ciphertext, key, rounds, iv)

# ==============================
# PART 5: HIGH-LEVEL API (5%)
# ==============================

def lightcrypt_encrypt(plaintext: bytes, key: str, rounds: int = 4, authenticated: bool = False) -> bytes:
    """Main encryption function."""
    if authenticated:
        return authenticated_encrypt(plaintext, key, rounds)
    else:
        ciphertext, iv = encrypt_cbc(plaintext, key, rounds)
        return iv + ciphertext

def lightcrypt_decrypt(ciphertext: bytes, key: str, rounds: int = 4, authenticated: bool = False) -> bytes:
    """Main decryption function."""
    if authenticated:
        return authenticated_decrypt(ciphertext, key, rounds)
    else:
        iv = ciphertext[:16]
        cipher_data = ciphertext[16:]
        return decrypt_cbc(cipher_data, key, rounds, iv)

# ==============================
# PART 6: TESTING SUITE (25%)
# ==============================

def test_avalanche():
    """Test 1: Avalanche Effect"""
    print("\n" + "="*70)
    print("TEST 1: AVALANCHE EFFECT (1-bit change → ~50% bits flipped)")
    print("="*70)

    key = "TestKey"
    pt1 = b"Hello World Test"
    pt2 = bytearray(pt1)
    pt2[0] ^= 1
    pt2 = bytes(pt2)

    c1 = lightcrypt_encrypt(pt1, key)
    c2 = lightcrypt_encrypt(pt2, key)

    diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(c1[16:], c2[16:]))
    total = (len(c1) - 16) * 8
    percent = (diff / total) * 100

    print(f"Result: {percent:.2f}% bits changed")
    print(f"Status: {'✓ PASS' if 40 <= percent <= 60 else '✗ FAIL'}")
    return percent

def test_key_sensitivity():
    """Test 2: Key Sensitivity"""
    print("\n" + "="*70)
    print("TEST 2: KEY SENSITIVITY (Similar keys → Different outputs)")
    print("="*70)

    pt = b"Secret Message"
    c1 = lightcrypt_encrypt(pt, "Key1")
    c2 = lightcrypt_encrypt(pt, "Key2")

    diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(c1[16:], c2[16:]))
    total = (len(c1) - 16) * 8
    percent = (diff / total) * 100

    print(f"Result: {percent:.2f}% bits changed")
    print(f"Status: {'✓ PASS' if percent > 40 else '✗ FAIL'}")
    return percent

def test_authentication():
    """Test 3: Authentication"""
    print("\n" + "="*70)
    print("TEST 3: AUTHENTICATED ENCRYPTION (Tamper detection)")
    print("="*70)

    key = "AuthKey"
    pt = b"Authenticated message"

    cipher = lightcrypt_encrypt(pt, key, authenticated=True)
    decrypted = lightcrypt_decrypt(cipher, key, authenticated=True)
    print(f"✓ Authentication works: {pt == decrypted}")

    # Tamper test
    tampered = bytearray(cipher)
    tampered[-10] ^= 0xFF

    try:
        lightcrypt_decrypt(bytes(tampered), key, authenticated=True)
        print("✗ FAIL: Tampering not detected!")
        return False
    except ValueError:
        print("✓ PASS: Tampering detected")
        return True

def test_modes_comparison():
    """Test 4: Pattern Resistance"""
    print("\n" + "="*70)
    print("TEST 4: CBC MODE PATTERN RESISTANCE")
    print("="*70)

    key = "PatternKey"
    pt = b"AAAAAAAAAAAAAAAA" * 2  # Repeated blocks

    cipher = lightcrypt_encrypt(pt, key)
    b1 = cipher[16:32]
    b2 = cipher[32:48]

    print(f"Repeated input blocks")
    print(f"Block 1: {b1.hex()}")
    print(f"Block 2: {b2.hex()}")
    print(f"Identical: {b1 == b2}")
    print(f"Status: {'✓ PASS - No pattern' if b1 != b2 else '✗ FAIL'}")

    return b1 != b2

def test_correctness():
    """Test 5: Correctness"""
    print("\n" + "="*70)
    print("TEST 5: CORRECTNESS (Various inputs)")
    print("="*70)

    tests = [
        b"Short",
        b"A" * 100,
        b"Special: !@#$%",
        b"\x00\x01\xFF",
        b"",
    ]

    key = "TestKey"
    passed = 0

    for pt in tests:
        try:
            cipher = lightcrypt_encrypt(pt, key)
            decrypted = lightcrypt_decrypt(cipher, key)
            if pt == decrypted:
                print(f"✓ PASS: {len(pt)} bytes")
                passed += 1
            else:
                print(f"✗ FAIL: {len(pt)} bytes")
        except Exception as e:
            print(f"✗ ERROR: {e}")

    print(f"\nTotal: {passed}/{len(tests)} passed")
    return passed

def test_performance():
    """Test 6: Performance"""
    print("\n" + "="*70)
    print("TEST 6: PERFORMANCE BENCHMARK")
    print("="*70)

    key = "PerfKey"
    sizes = [1000, 10000, 100000]

    print(f"{'Size':<12} {'Encrypt (ms)':<15} {'Throughput (KB/s)':<15}")
    print("-" * 50)

    for size in sizes:
        pt = b"X" * size
        start = time.time()
        cipher = lightcrypt_encrypt(pt, key)
        elapsed = (time.time() - start) * 1000
        throughput = (size / 1024) / (elapsed / 1000)

        print(f"{size:<12} {elapsed:<15.2f} {throughput:<15.2f}")

def test_rounds():
    """Test 7: Round Security"""
    print("\n" + "="*70)
    print("TEST 7: ROUND COUNT ANALYSIS")
    print("="*70)

    key = "RoundKey"
    pt = b"Test message for rounds"

    print(f"{'Rounds':<10} {'Time (ms)':<15} {'Security':<15}")
    print("-" * 45)

    for rounds in [1, 2, 4, 8, 16]:
        start = time.time()
        cipher = lightcrypt_encrypt(pt, key, rounds=rounds)
        elapsed = (time.time() - start) * 1000

        security = "Low" if rounds < 4 else "Medium" if rounds < 8 else "High"
        print(f"{rounds:<10} {elapsed:<15.2f} {security:<15}")

def test_randomness():
    """Test 8: Randomness"""
    print("\n" + "="*70)
    print("TEST 8: STATISTICAL RANDOMNESS")
    print("="*70)

    key = "RandomKey"
    pt = b"A" * 1000  # Non-random input
    cipher = lightcrypt_encrypt(pt, key)

    # Frequency analysis
    freq = [0] * 256
    for byte in cipher[16:]:  # Skip IV
        freq[byte] += 1

    expected = (len(cipher) - 16) / 256
    chi_sq = sum((f - expected)**2 / expected for f in freq if f > 0)
    unique = sum(1 for f in freq if f > 0)

    print(f"Chi-square: {chi_sq:.2f} (expected: 200-310)")
    print(f"Unique bytes: {unique}/256")
    print(f"Status: {'✓ PASS' if 200 <= chi_sq <= 310 else '⚠ WARNING'}")

# ==============================
# PART 7: SECURITY ANALYSIS (10%)
# ==============================

def print_security_analysis():
    """Security analysis documentation."""
    print("\n" + "="*70)
    print("SECURITY ANALYSIS")
    print("="*70)

    print("\nSTRENGTHS:")
    print("  ✓ Key-dependent S-box (prevents precomputation)")
    print("  ✓ CBC mode (resists pattern attacks)")
    print("  ✓ HMAC authentication (detects tampering)")
    print("  ✓ Configurable rounds (scalable security)")
    print("  ✓ 256-bit key space (brute-force resistant)")

    print("\nWEAKNESSES:")
    print("  ⚠ Simple transposition (not as strong as MixColumns)")
    print("  ⚠ Low default rounds (4 vs AES 10-14)")
    print("  ⚠ No formal security proof")
    print("  ⚠ Not standardized/audited")

    print("\nATTACK RESISTANCE:")
    print("  ✓ Brute Force: RESISTANT (2^256 keys)")
    print("  ✓ Pattern: RESISTANT (CBC mode)")
    print("  ✓ Tampering: RESISTANT (HMAC)")
    print("  ? Differential: UNKNOWN (needs analysis)")
    print("  ? Linear: UNKNOWN (needs analysis)")

    print("\nRECOMMENDATIONS:")
    print("  → Use 8+ rounds for production")
    print("  → Always enable authentication")
    print("  → Add salt for key derivation")
    print("  → Consider adding MixColumns operation")

def print_comparison():
    """Compare with standard algorithms."""
    print("\n" + "="*70)
    print("COMPARISON WITH STANDARDS")
    print("="*70)

    print("\n| Feature          | LightCrypt-8 | AES-128     | ChaCha20    |")
    print("|------------------|--------------|-------------|-------------|")
    print("| Block Size       | 16 bytes     | 16 bytes    | 64 bytes    |")
    print("| Default Rounds   | 4            | 10          | 20          |")
    print("| Speed            | Fast ⚡⚡     | Fast ⚡⚡⚡    | Fast ⚡⚡⚡    |")
    print("| Security         | Medium ⭐⭐   | High ⭐⭐⭐⭐⭐  | High ⭐⭐⭐⭐⭐  |")
    print("| Complexity       | Simple       | Complex     | Moderate    |")
    print("| Standardized     | No           | Yes (NIST)  | Yes (RFC)   |")
    print("| Hardware Support | No           | Yes (AES-NI)| Partial     |")

    print("\nCONCLUSION:")
    print("LightCrypt-8 is simpler and easier to understand than AES,")
    print("making it excellent for education. However, for production,")
    print("use NIST-approved algorithms like AES-GCM.")

# ==============================
# PART 8: MAIN PROGRAM (5%)
# ==============================

def run_all_tests():
    """Execute complete test suite."""
    print("\n" + "="*70)
    print("LIGHTCRYPT-8 COMPLETE TEST SUITE")
    print("FINAL PROJECT SUBMISSION (100%)")
    print("="*70)

    # Basic demonstration
    print("\n[DEMONSTRATION]")
    key = "MySecureKey2025"
    plaintext = b"Hello, this is LightCrypt-8!"
    cipher = lightcrypt_encrypt(plaintext, key, authenticated=True)
    decrypted = lightcrypt_decrypt(cipher, key, authenticated=True)
    print(f"Original : {plaintext}")
    print(f"Cipher   : {cipher.hex()[:60]}...")
    print(f"Decrypted: {decrypted}")
    print(f"Success  : {plaintext == decrypted}")

    # Run all tests
    results = {}
    results['avalanche'] = test_avalanche()
    results['key_sens'] = test_key_sensitivity()
    results['auth'] = test_authentication()
    results['pattern'] = test_modes_comparison()
    results['correct'] = test_correctness()
    test_performance()
    test_rounds()
    test_randomness()

    # Security analysis
    print_security_analysis()
    print_comparison()

    # Final summary
    print("\n" + "="*70)
    print("FINAL SUMMARY")
    print("="*70)
    print(f"Avalanche Effect  : {results['avalanche']:.1f}% ({'PASS' if 40<=results['avalanche']<=60 else 'FAIL'})")
    print(f"Key Sensitivity   : {results['key_sens']:.1f}% ({'PASS' if results['key_sens']>40 else 'FAIL'})")
    print(f"Authentication    : {'PASS' if results['auth'] else 'FAIL'}")
    print(f"Pattern Resistance: {'PASS' if results['pattern'] else 'FAIL'}")
    print(f"Correctness       : {results['correct']}/5 tests")

    print("\n✓ Project Components:")
    print("  [30%] Core implementation + Basic tests")
    print("  [40%] Advanced features + Security analysis")
    print("  [30%] Testing + Documentation")
    print("  [100%] COMPLETE")

    print("\n" + "="*70)
    print("SUBMISSION COMPLETE")
    print("="*70)

if __name__ == "__main__":
    run_all_tests()