#include <crypto.h>
#include <string.h>

// SHA256 constants
static const uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define SHR(x,n)  ((x)>>(n))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define BSIG0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define BSIG1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SSIG0(x) (ROTR(x,7)^ROTR(x,18)^SHR(x,3))
#define SSIG1(x) (ROTR(x,17)^ROTR(x,19)^SHR(x,10))

void sha256(const unsigned char *data, size_t len, uint32_t out_digest[8]) {
  // Hash value initialization
  uint32_t h[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
  };
  size_t i;

  // Pre-processing
  size_t new_len = len + 1;
  while ((new_len % 64) != 56) new_len++;
  unsigned char buf[128]; // enough for one block + padding
  size_t offset = 0;

  // Process all full blocks
  while (offset + 64 <= len) {
    uint32_t w[64];
    for (i = 0; i < 16; i++) {
      w[i] = (data[offset + 4*i] << 24) | (data[offset + 4*i + 1] << 16) |
             (data[offset + 4*i + 2] << 8) | (data[offset + 4*i + 3]);
    }
    for (i = 16; i < 64; i++) {
      w[i] = SSIG1(w[i-2]) + w[i-7] + SSIG0(w[i-15]) + w[i-16];
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], h_ = h[7];
    for (i = 0; i < 64; i++) {
      uint32_t t1 = h_ + BSIG1(e) + CH(e,f,g) + k[i] + w[i];
      uint32_t t2 = BSIG0(a) + MAJ(a,b,c);
      h_ = g; g = f; f = e; e = d + t1;
      d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_;
    offset += 64;
  }

  // Padding
  size_t rem = len - offset;
  memset(buf, 0, 64);
  if (rem) memcpy(buf, data + offset, rem);
  buf[rem] = 0x80;
  if (rem >= 56) {
    // Not enough space for length, process this block
    for (i = 0; i < 16; i++) {
      uint32_t w = (buf[4*i] << 24) | (buf[4*i+1] << 16) | (buf[4*i+2] << 8) | (buf[4*i+3]);
      buf[4*i] = (w >> 24) & 0xff;
      buf[4*i+1] = (w >> 16) & 0xff;
      buf[4*i+2] = (w >> 8) & 0xff;
      buf[4*i+3] = w & 0xff;
    }
    uint32_t w[64];
    for (i = 0; i < 16; i++) {
      w[i] = (buf[4*i] << 24) | (buf[4*i+1] << 16) | (buf[4*i+2] << 8) | (buf[4*i+3]);
    }
    for (i = 16; i < 64; i++) {
      w[i] = SSIG1(w[i-2]) + w[i-7] + SSIG0(w[i-15]) + w[i-16];
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], h_ = h[7];
    for (i = 0; i < 64; i++) {
      uint32_t t1 = h_ + BSIG1(e) + CH(e,f,g) + k[i] + w[i];
      uint32_t t2 = BSIG0(a) + MAJ(a,b,c);
      h_ = g; g = f; f = e; e = d + t1;
      d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_;
    memset(buf, 0, 64);
  }
  // Append length in bits
  uint64_t bits = ((uint64_t)len) * 8;
  buf[56] = (bits >> 56) & 0xff;
  buf[57] = (bits >> 48) & 0xff;
  buf[58] = (bits >> 40) & 0xff;
  buf[59] = (bits >> 32) & 0xff;
  buf[60] = (bits >> 24) & 0xff;
  buf[61] = (bits >> 16) & 0xff;
  buf[62] = (bits >> 8) & 0xff;
  buf[63] = bits & 0xff;
  uint32_t w[64];
  for (i = 0; i < 16; i++) {
    w[i] = (buf[4*i] << 24) | (buf[4*i+1] << 16) | (buf[4*i+2] << 8) | (buf[4*i+3]);
  }
  for (i = 16; i < 64; i++) {
    w[i] = SSIG1(w[i-2]) + w[i-7] + SSIG0(w[i-15]) + w[i-16];
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
  uint32_t e = h[4], f = h[5], g = h[6], h_ = h[7];
  for (i = 0; i < 64; i++) {
    uint32_t t1 = h_ + BSIG1(e) + CH(e,f,g) + k[i] + w[i];
    uint32_t t2 = BSIG0(a) + MAJ(a,b,c);
    h_ = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  h[4] += e; h[5] += f; h[6] += g; h[7] += h_;

  for (i = 0; i < 8; i++) {
    out_digest[i] = h[i];
  }
}
