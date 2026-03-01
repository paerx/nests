(() => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function utf8ToBytes(str) {
    return encoder.encode(str);
  }

  function bytesToUtf8(bytes) {
    return decoder.decode(bytes);
  }

  function toHex(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function fromHex(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  function base64Encode(bytes) {
    let binary = "";
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary);
  }

  function base64Decode(str) {
    const binary = atob(str);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }

  function isBase64(str) {
    if (!str || str.length % 4 !== 0) return false;
    return /^[A-Za-z0-9+/=]+$/.test(str);
  }

  function sha256Hex(str) {
    return crypto.subtle
      .digest("SHA-256", utf8ToBytes(str))
      .then((buf) => toHex(new Uint8Array(buf)));
  }

  function randomBytes(length) {
    const out = new Uint8Array(length);
    crypto.getRandomValues(out);
    return out;
  }

  function pkcs7Pad(data, blockSize) {
    const rem = data.length % blockSize;
    const padLen = rem === 0 ? blockSize : blockSize - rem;
    const out = new Uint8Array(data.length + padLen);
    out.set(data);
    out.fill(padLen, data.length);
    return out;
  }

  function pkcs7Unpad(data) {
    const pad = data[data.length - 1];
    return data.slice(0, data.length - pad);
  }

  function rotl(x, n) {
    return (x << n) | (x >>> (32 - n));
  }

  function p0(x) {
    return x ^ rotl(x, 9) ^ rotl(x, 17);
  }

  function p1(x) {
    return x ^ rotl(x, 15) ^ rotl(x, 23);
  }

  function sm3(bytes) {
    const iv = [
      0x7380166f,
      0x4914b2b9,
      0x172442d7,
      0xda8a0600,
      0xa96f30bc,
      0x163138aa,
      0xe38dee4d,
      0xb0fb0e4e,
    ];

    const len = bytes.length * 8;
    let k = (448 - (len + 1)) % 512;
    if (k < 0) k += 512;
    const paddingLen = ((k + 1 + 64) / 8) | 0;
    const padded = new Uint8Array(bytes.length + paddingLen);
    padded.set(bytes);
    padded[bytes.length] = 0x80;

    const lenPos = padded.length - 8;
    for (let i = 0; i < 8; i++) {
      padded[lenPos + i] = (len >>> (56 - 8 * i)) & 0xff;
    }

    const w = new Uint32Array(68);
    const w1 = new Uint32Array(64);

    const t = [
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x79cc4519,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
      0x7a879d8a,
    ];

    let v = iv.slice();

    for (let i = 0; i < padded.length; i += 64) {
      for (let j = 0; j < 16; j++) {
        const idx = i + j * 4;
        w[j] =
          (padded[idx] << 24) |
          (padded[idx + 1] << 16) |
          (padded[idx + 2] << 8) |
          padded[idx + 3];
      }
      for (let j = 16; j < 68; j++) {
        const x = w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15);
        w[j] = p1(x) ^ rotl(w[j - 13], 7) ^ w[j - 6];
      }
      for (let j = 0; j < 64; j++) {
        w1[j] = w[j] ^ w[j + 4];
      }

      let [a, b, c, d, e, f, g, h] = v;
      for (let j = 0; j < 64; j++) {
        const ss1 = rotl(((rotl(a, 12) + e + rotl(t[j], j)) >>> 0), 7);
        const ss2 = ss1 ^ rotl(a, 12);
        const ff = j < 16 ? a ^ b ^ c : (a & b) | (a & c) | (b & c);
        const gg = j < 16 ? e ^ f ^ g : (e & f) | (~e & g);
        const tt1 = (ff + d + ss2 + w1[j]) >>> 0;
        const tt2 = (gg + h + ss1 + w[j]) >>> 0;
        d = c;
        c = rotl(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rotl(f, 19);
        f = e;
        e = p0(tt2);
      }

      v = [
        a ^ v[0],
        b ^ v[1],
        c ^ v[2],
        d ^ v[3],
        e ^ v[4],
        f ^ v[5],
        g ^ v[6],
        h ^ v[7],
      ];
    }

    const out = new Uint8Array(32);
    v.forEach((val, i) => {
      out[i * 4] = (val >>> 24) & 0xff;
      out[i * 4 + 1] = (val >>> 16) & 0xff;
      out[i * 4 + 2] = (val >>> 8) & 0xff;
      out[i * 4 + 3] = val & 0xff;
    });
    return out;
  }

  function hmacSm3(key, msg) {
    const blockSize = 64;
    let k = key;
    if (k.length > blockSize) {
      k = sm3(k);
    }
    if (k.length < blockSize) {
      const padded = new Uint8Array(blockSize);
      padded.set(k);
      k = padded;
    }
    const oKey = new Uint8Array(blockSize);
    const iKey = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      oKey[i] = k[i] ^ 0x5c;
      iKey[i] = k[i] ^ 0x36;
    }
    const inner = sm3(concatBytes(iKey, msg));
    return sm3(concatBytes(oKey, inner));
  }

  function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a);
    out.set(b, a.length);
    return out;
  }

  function hkdfSm3(ikm, salt, info, length) {
    const prk = hmacSm3(salt, ikm);
    let t = new Uint8Array(0);
    let okm = new Uint8Array(0);
    let i = 1;
    while (okm.length < length) {
      const input = concatBytes(concatBytes(t, info), new Uint8Array([i]));
      t = hmacSm3(prk, input);
      okm = concatBytes(okm, t);
      i++;
    }
    return okm.slice(0, length);
  }

  const sbox = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
  ];

  const fk = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
  const ck = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
  ];

  function tau(a) {
    return (
      (sbox[(a >>> 24) & 0xff] << 24) |
      (sbox[(a >>> 16) & 0xff] << 16) |
      (sbox[(a >>> 8) & 0xff] << 8) |
      sbox[a & 0xff]
    ) >>> 0;
  }

  function l1(b) {
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
  }

  function l2(b) {
    return b ^ rotl(b, 13) ^ rotl(b, 23);
  }

  function sm4KeyExpand(key) {
    const mk = new Uint32Array(4);
    for (let i = 0; i < 4; i++) {
      mk[i] =
        (key[i * 4] << 24) |
        (key[i * 4 + 1] << 16) |
        (key[i * 4 + 2] << 8) |
        key[i * 4 + 3];
    }

    const k = new Uint32Array(36);
    for (let i = 0; i < 4; i++) {
      k[i] = mk[i] ^ fk[i];
    }

    const rk = new Uint32Array(32);
    for (let i = 0; i < 32; i++) {
      const t = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck[i];
      k[i + 4] = k[i] ^ l2(tau(t));
      rk[i] = k[i + 4];
    }
    return rk;
  }

  function sm4CryptBlock(input, rk) {
    const x = new Uint32Array(36);
    for (let i = 0; i < 4; i++) {
      x[i] =
        (input[i * 4] << 24) |
        (input[i * 4 + 1] << 16) |
        (input[i * 4 + 2] << 8) |
        input[i * 4 + 3];
    }
    for (let i = 0; i < 32; i++) {
      const t = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i];
      x[i + 4] = x[i] ^ l1(tau(t));
    }
    const out = new Uint8Array(16);
    for (let i = 0; i < 4; i++) {
      const val = x[35 - i];
      out[i * 4] = (val >>> 24) & 0xff;
      out[i * 4 + 1] = (val >>> 16) & 0xff;
      out[i * 4 + 2] = (val >>> 8) & 0xff;
      out[i * 4 + 3] = val & 0xff;
    }
    return out;
  }

  function sm4EncryptCbc(key, iv, data) {
    const rk = sm4KeyExpand(key);
    const padded = pkcs7Pad(data, 16);
    const out = new Uint8Array(padded.length);
    let prev = iv;
    for (let i = 0; i < padded.length; i += 16) {
      const block = padded.slice(i, i + 16);
      for (let j = 0; j < 16; j++) {
        block[j] ^= prev[j];
      }
      const enc = sm4CryptBlock(block, rk);
      out.set(enc, i);
      prev = enc;
    }
    return out;
  }

  function sm4DecryptCbc(key, iv, data) {
    const rk = sm4KeyExpand(key);
    const rkRev = rk.slice().reverse();
    const out = new Uint8Array(data.length);
    let prev = iv;
    for (let i = 0; i < data.length; i += 16) {
      const block = data.slice(i, i + 16);
      const dec = sm4CryptBlock(block, rkRev);
      for (let j = 0; j < 16; j++) {
        dec[j] ^= prev[j];
      }
      out.set(dec, i);
      prev = block;
    }
    return pkcs7Unpad(out);
  }

  function deriveEnvKey(globalKey, kdfSalt, name) {
    const saltBytes = isBase64(kdfSalt) ? base64Decode(kdfSalt) : utf8ToBytes(kdfSalt || "");
    const info = utf8ToBytes(name);
    return hkdfSm3(utf8ToBytes(globalKey), saltBytes, info, 16);
  }

  function encryptValue(plainText, keyBytes) {
    const iv = randomBytes(16);
    const data = utf8ToBytes(plainText);
    const enc = sm4EncryptCbc(keyBytes, iv, data);
    const combined = concatBytes(iv, enc);
    return base64Encode(combined);
  }

  function decryptValue(encoded, keyBytes) {
    const combined = base64Decode(encoded);
    const iv = combined.slice(0, 16);
    const ciphertext = combined.slice(16);
    const dec = sm4DecryptCbc(keyBytes, iv, ciphertext);
    return bytesToUtf8(dec);
  }

  function signEDatas(eDatas, keyBytes) {
    const compact = eDatas.map((e) => ({ e_key: e.e_key, e_value: e.e_value }));
    const payload = utf8ToBytes(JSON.stringify(compact));
    return toHex(hmacSm3(keyBytes, payload));
  }

  window.NestsCrypto = {
    utf8ToBytes,
    bytesToUtf8,
    base64Encode,
    base64Decode,
    sha256Hex,
    randomBytes,
    deriveEnvKey,
    encryptValue,
    decryptValue,
    signEDatas,
    hmacSm3,
    sm3,
    toHex,
    fromHex,
  };
})();
