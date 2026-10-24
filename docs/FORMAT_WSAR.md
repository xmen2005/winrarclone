# WSAR — Open RAR5-style container specification (v1)

`WSAR` is the native container of this project. It is **inspired by the RAR5
header model** but intentionally not bit-compatible with any proprietary format.

All integers are **little-endian**. Text is UTF-8.

## 1. Signature (first 8 bytes of part 1)

| Offset | Size | Value |
|--------|------|-------|
| 0 | 4 | `'W','S','A','R'` (0x57 0x53 0x41 0x52) |
| 4 | 4 | `0x1A 0x07 0x01 0x00` (RAR5-style signature echo) |

## 2. Header frame (repeated for every record)

```
u8   magic[8]      WSAR signature (repeated before every frame)
u32  crc32         CRC32 of the bytes AFTER this field through end of payload
u16  headerSize    payload size in bytes
u8   type          1=MAIN 2=FILE 3=END
u8   flags         reserved (0)
u16  reserved      0
u64  dataLen       size of the data region following the frame (plaintext)
u8   payload[headerSize]
u8   data[dataLen]                (absent when dataLen == 0)
```

Frame fixed size = 24 bytes.

## 3. MAIN header (type 1) — always first

```
u64  dictSize       dictionary size in bytes (1 MB … 64 GB)
u32  archiveFlags   0x01 multi-volume  0x02 encrypted-names  0x04 solid (reserved)
u64  volumeSize     bytes per volume (0 = single file) — v1.1 archives;
                     readers of v1.0 archives must treat the remaining
                     payload as the salt length field instead
if (a salt follows — i.e. payload has ≥ 4 more bytes):
    u32 saltLen     16
    u8  salt[16]    PBKDF2 salt (stored whenever any encryption is used)
```

## 4. FILE header (type 2)

Plaintext payload layout:

```
u64  origSize
u64  packedSize     == frame dataLen
u32  crc32          CRC32 of the ORIGINAL (uncompressed) data
u32  attrs          Windows attributes
u64  mtime          Unix seconds (UTC)
u8   method         0=Store 1=Deflate 2=LZSS
u8   encFlag        0x01 = data region encrypted (AES-256-CBC)
u16  nameLen
u8   name[nameLen]  relative path, '/' separators ('/' suffix marks directories)
```

Data region (dataLen bytes):

* unencrypted: raw packed bytes
* encrypted (encFlag bit0): `[16B IV][AES-256-CBC(cipher)][16B HMAC-SHA256 tag]`
  — the tag authenticates IV+ciphertext, verified before decryption.

### Encrypted file names

If `archiveFlags & 0x02`, the FILE header payload is stored encrypted:

```
u8   encPayload[headerSize] = [16B IV][AES-256-CBC(payload)][16B HMAC tag]
```

The MAIN header is always plaintext, so readers can locate the salt and
derive the name key before parsing file headers.

## 5. END header (type 3) — last record

```
u32 volumeCount    number of volume parts (1 = single file)
u32 endFlags       reserved (0)
```

## 6. Multi-volume

Part file names: `<base>.part00001.wrc`, `<base>.part00002.wrc`, …
Part 1 carries the signature + MAIN; parts ≥ 2 are **raw continuation
slices** of the logical byte stream (no separate headers). Readers open all
parts in order and treat them as one logical stream.

## 7. Crypto (Windows CNG)

* Key derivation: `PBKDF2-HMAC-SHA256(password, salt‖info, 200_000, 32)` —
  `info = 0x01` for the data key, `0x02` for the header/name key.
* Cipher: AES-256-CBC, PKCS#7 padding, random 16-byte IV per encrypted blob.
* Integrity: encrypt-then-MAC, `HMAC-SHA256(key, iv‖ciphertext)` truncated
  to 16 bytes, verified before decryption.
