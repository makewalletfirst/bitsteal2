import hashlib
import struct
import time

def sha256d(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def little_endian_hex(hexstr):
    ba = bytearray.fromhex(hexstr)
    ba.reverse()
    return ba.hex()

def create_genesis_block(version, prev_block, merkle_root, time, bits, nonce):
    header = (
        struct.pack("<L", version) +
        bytes.fromhex(prev_block)[::-1] +
        bytes.fromhex(merkle_root)[::-1] +
        struct.pack("<L", time) +
        struct.pack("<L", bits) +
        struct.pack("<L", nonce)
    )
    return header

def mine_genesis_block(target, version, prev_block, merkle_root, time, bits):
    max_nonce = 0xFFFFFFFF
    print("Merkle Root:", merkle_root)
    for nonce in range(max_nonce):
        header = create_genesis_block(version, prev_block, merkle_root, time, bits, nonce)
        hash_result = sha256d(header)[::-1].hex()
        if hash_result < target:
            print("\n=== Found Genesis Block ===")
            print("Time:", time)
            print("Nonce:", nonce)
            print("Bits:", hex(bits))
            print("Merkle Root:", merkle_root)
            print("Hash:", hash_result)
            return
        if nonce % 100000 == 0:
            print("Checked nonce:", nonce)
    print("Genesis block not found.")

if __name__ == "__main__":
    # BitSteal 제네시스 파라미터
    version = 1
    prev_block = "00" * 32
    # 꼭! CreateGenesisBlock에서 생성한 트랜잭션의 Merkle Root로 넣어야 함
    merkle_root = "c58250dd67353779e63f8071309ba61f3e0bcb875471630a481915b778430309"
    time_val = 1753150989
    bits = 0x1f00ffff

    # target 계산 (bits 기준)
    exponent = bits >> 24
    coefficient = bits & 0xffffff
    target_hex = (coefficient * (1 << (8 * (exponent - 3)))).to_bytes(32, byteorder='big').hex()
    print("Target:", target_hex)

    mine_genesis_block(target_hex, version, prev_block, merkle_root, time_val, bits)

