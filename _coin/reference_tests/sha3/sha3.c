    // Copyright (c) 2008, Lawrence E. Bassham, National Institute of Standards and Technology (NIST),
    // for the original version (available at http://csrc.nist.gov/groups/ST/hash/sha-3/documents/KAT1.zip)

    // All rights reserved.

    // Redistribution and use in source and binary forms, with or without
    // modification, are permitted provided that the following conditions are met:
    //     * Redistributions of source code must retain the above copyright
    //     notice, this list of conditions and the following disclaimer.
    //     * Redistributions in binary form must reproduce the above copyright
    //     notice, this list of conditions and the following disclaimer in the
    //     documentation and/or other materials provided with the distribution.
    //     * Neither the name of the NIST nor the
    //     names of its contributors may be used to endorse or promote products
    //     derived from this software without specific prior written permission.

    // THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    // ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    // WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    // DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
    // DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    // (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    // LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    // ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    // (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    // SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stddef.h>
#include <stdint.h>

#define FOR(i,n) for(i=0; i<n; ++i)
typedef unsigned char u8;
typedef unsigned long long int u64;
typedef unsigned int ui;

void Keccak(ui r, ui c, const u8 *in, u64 inLen, u8 sfx, u8 *out, u64 outLen);
void FIPS202_SHAKE128(const u8 *in, u64 inLen, u8 *out, u64 outLen) { Keccak(1344, 256, in, inLen, 0x1F, out, outLen); }
void FIPS202_SHAKE256(const u8 *in, u64 inLen, u8 *out, u64 outLen) { Keccak(1088, 512, in, inLen, 0x1F, out, outLen); }
void FIPS202_SHA3_224(const u8 *in, u64 inLen, u8 *out) { Keccak(1152, 448, in, inLen, 0x06, out, 28); }
void FIPS202_SHA3_256(const u8 *in, u64 inLen, u8 *out) { Keccak(1088, 512, in, inLen, 0x06, out, 32); }
void FIPS202_SHA3_384(const u8 *in, u64 inLen, u8 *out) { Keccak(832, 768, in, inLen, 0x06, out, 48); }
void FIPS202_SHA3_512(const u8 *in, u64 inLen, u8 *out) { Keccak(576, 1024, in, inLen, 0x06, out, 64); }

int LFSR86540(u8 *R) { (*R)=((*R)<<1)^(((*R)&0x80)?0x71:0); return ((*R)&2)>>1; }
#define ROL(a,o) ((((u64)a)<<o)^(((u64)a)>>(64-o)))
static u64 load64(const u8 *x) { ui i; u64 u=0; FOR(i,8) { u<<=8; u|=x[7-i]; } return u; }
static void store64(u8 *x, u64 u) { ui i; FOR(i,8) { x[i]=u; u>>=8; } }
static void xor64(u8 *x, u64 u) { ui i; FOR(i,8) { x[i]^=u; u>>=8; } }
#define rL(x,y) load64((u8*)s+8*(x+5*y))
#define wL(x,y,l) store64((u8*)s+8*(x+5*y),l)
#define XL(x,y,l) xor64((u8*)s+8*(x+5*y),l)
void KeccakF1600(void *s)
{
    ui r,x,y,i,j,Y; u8 R=0x01; u64 C[5],D;
    for(i=0; i<24; i++) {
        /*θ*/ FOR(x,5) C[x]=rL(x,0)^rL(x,1)^rL(x,2)^rL(x,3)^rL(x,4); FOR(x,5) { D=C[(x+4)%5]^ROL(C[(x+1)%5],1); FOR(y,5) XL(x,y,D); }
        /*ρπ*/ x=1; y=r=0; D=rL(x,y); FOR(j,24) { r+=j+1; Y=(2*x+3*y)%5; x=y; y=Y; C[0]=rL(x,y); wL(x,y,ROL(D,r%64)); D=C[0]; }
        /*χ*/ FOR(y,5) { FOR(x,5) C[x]=rL(x,y); FOR(x,5) wL(x,y,C[x]^((~C[(x+1)%5])&C[(x+2)%5])); }
        /*ι*/ FOR(j,7) if (LFSR86540(&R)) XL(0,0,(u64)1<<((1<<j)-1));
    }
}
void Keccak(ui r, ui c, const u8 *in, u64 inLen, u8 sfx, u8 *out, u64 outLen)
{
    /*initialize*/ u8 s[200]; ui R=r/8; ui i,b=0; FOR(i,200) s[i]=0;
    /*absorb*/ while(inLen>0) { b=(inLen<R)?inLen:R; FOR(i,b) s[i]^=in[i]; in+=b; inLen-=b; if (b==R) { KeccakF1600(s); b=0; } }
    /*pad*/ s[b]^=sfx; if((sfx&0x80)&&(b==(R-1))) KeccakF1600(s); s[R-1]^=0x80; KeccakF1600(s);
    /*squeeze*/ while(outLen>0) { b=(outLen<R)?outLen:R; FOR(i,b) out[i]=s[i]; out+=b; outLen-=b; if(outLen>0) KeccakF1600(s); }
}

/* Convenience functions for SHA3-256 (similar to SHA256 API) */
void sha3_256_easy_hash(const void* data, size_t size, uint8_t* hash)
{
    FIPS202_SHA3_256((const u8*)data, (u64)size, hash);
}

void sha3_256_to_hex(const uint8_t* hash, char* hex)
{
    const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2] = hex_chars[(hash[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hex_chars[hash[i] & 0xF];
    }
}

void sha3_256_easy_hash_hex(const void* data, size_t size, char* hex)
{
    uint8_t hash[32];
    sha3_256_easy_hash(data, size, hash);
    sha3_256_to_hex(hash, hex);
}

#include <string.h> // Included for memcmp to compare hashes.

// The memory address from which the test case index will be read.
#define INPUT_ADDRESS 0xAA000000
#include "test_vectors.h"

int main()
{
    uint8_t actual_hash[32]; // Buffer to store the generated hash.
    const SHA3TestVector *selected_test;
    unsigned int test_index = *(unsigned int*)INPUT_ADDRESS;

    // 2. Perform a bounds check to prevent reading past the end of the array.
    // We use `num_sha3_256_test_vectors` which is defined in the generated "test_vectors.h".
    if (test_index >= num_sha3_256_test_vectors)
    {
        // Return a distinct error code if the index is out of bounds.
        return 42;
    }

    // Select the test case from the array defined in "test_vectors.h".
    selected_test = &sha3_256_test_vectors[test_index];

    // 3. Compute the SHA3-256 hash of the message from the selected test vector.
    // The `sha3_256_easy_hash` function handles the hash computation in one call.
    sha3_256_easy_hash(selected_test->message, selected_test->message_len, actual_hash);

    // 4. Compare the generated hash with the expected hash.
    // `memcmp` returns 0 if the memory regions are identical.
    if (0 == memcmp(actual_hash, selected_test->expected_hash, sizeof(actual_hash)))
    {
        // Success: The generated hash matches the known answer.
        return 0;
    }
    else
    {
        // Failure: The generated hash does not match the expected value.
        return 1;
    }
}