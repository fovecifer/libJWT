#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

#include "cJSON.h"
#include "libJWT.h"


#define LIKELY_IS(x,y)	__builtin_expect((x), (y))
#define LIKELY(x)	LIKELY_IS(!!(x), 1)
#define UNLIKELY(x)	LIKELY_IS((x), 0)

typedef struct {
    size_t len;
    u_char *data;
} str_t;

#define base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define base64_decoded_length(len)  (((len + 3) / 4) * 3)

#define BN_base64_encoded_length(bn) (base64_encoded_length(BN_num_bytes(bn)))

static void
encode_base64_internal(str_t *dst, str_t *src, const u_char *basis,
        uintptr_t padding) {
    u_char *d, *s;
    size_t len;

    len = src->len;
    s = src->data;
    d = dst->data;

    while (len > 2) {
        *d++ = basis[(s[0] >> 2) & 0x3f];
        *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis[s[2] & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = basis[(s[0] >> 2) & 0x3f];

        if (len == 1) {
            *d++ = basis[(s[0] & 3) << 4];
            if (padding) {
                *d++ = '=';
            }

        } else {
            *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis[(s[1] & 0x0f) << 2];
        }

        if (padding) {
            *d++ = '=';
        }
    }

    dst->len = d - dst->data;
}

static int
decode_base64_internal(str_t *dst, str_t *src, const u_char *basis) {
    size_t len;
    u_char *d, *s;

    for (len = 0; len < src->len; len++) {
        if (src->data[len] == '=') {
            break;
        }

        if (basis[src->data[len]] == 77) {
            return -1;
        }
    }

    if (len % 4 == 1) {
        return -1;
    }

    s = src->data;
    d = dst->data;

    while (len > 3) {
        *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
        *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
        *d++ = (u_char) (basis[s[2]] << 6 | basis[s[3]]);

        s += 4;
        len -= 4;
    }

    if (len > 1) {
        *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
    }

    if (len > 2) {
        *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
    }

    dst->len = d - dst->data;

    return 0;
}

static int
ngx_decode_base64(str_t *dst, str_t *src) {
    static u_char basis64[] = {
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
        77, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
        77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
    };

    return decode_base64_internal(dst, src, basis64);
}

static int
decode_base64url(str_t *dst, str_t *src) {
    static u_char basis64[] = {
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
        77, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 63,
        77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
    };

    return decode_base64_internal(dst, src, basis64);
}

static void
encode_base64(str_t *dst, str_t *src) {
    static u_char basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    encode_base64_internal(dst, src, basis64, 1);
}

static void
encode_base64url(str_t *dst, str_t *src) {
    static u_char basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    encode_base64_internal(dst, src, basis64, 0);
}

static int
token_sign(str_t *header, str_t *claim, str_t *sign, EVP_PKEY *key) {
    EVP_MD_CTX *mdctx;
    size_t req;
    int ret;
    
    if((mdctx = EVP_MD_CTX_create()) == NULL) {
        return -1;
    }
    if((EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key)) != 1) {
        return -1;
    }
    if((EVP_DigestSignUpdate(mdctx, header->data, header->len)) != 1) {
        return -1;
    }
    if((EVP_DigestSignUpdate(mdctx, ".", 1)) != 1) {
        return -1;
    }
    if((EVP_DigestSignUpdate(mdctx, claim->data, claim->len)) != 1) {
        return -1;
    }
    if((EVP_DigestSignFinal(mdctx, NULL, &req)) != 1) {
        return -1;
    }
    if(req > sign->len) {
        return -2;
    }
    ret = EVP_DigestSignFinal(mdctx, sign->data, &sign->len);
    EVP_MD_CTX_destroy(mdctx);
    return ret;
}

static int
token_verify(str_t *token, EVP_PKEY *key) {
    size_t i = token->len - 1;
    size_t flag;
    int ret;
    EVP_MD_CTX *mdctx;

    for (; i >= 0; i--) {
        if (token->data[i] == '.') break;
    }
    /* invalidate token */
    if (i < 0) {
        return -1;
    }
    flag = i;
    
    str_t pay_load = {
        .data = token->data,
        .len = flag
    };

    /* sign */
    str_t sign_hash = {
        .data = token->data + flag + 1,
        .len = token->len - flag - 1
    };
    u_char sign_data[base64_decoded_length(sign_hash.len)];
    str_t sign = {
        .data = sign_data,
        .len = base64_decoded_length(sign_hash.len)
    };
    decode_base64url(&sign, &sign_hash);
    
    if((mdctx = EVP_MD_CTX_create()) == NULL) {
        return -1;
    }
    if((EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key)) != 1) {
        return -1;
    }
    if((EVP_DigestVerifyUpdate(mdctx, pay_load.data, pay_load.len)) != 1) {
        return -1;
    }
    ret = EVP_DigestVerifyFinal(mdctx, sign.data, sign.len);
    EVP_MD_CTX_destroy(mdctx);
    return ret;
}


int 
jwt_load_pub(libjwt_t *jwt, const char *key_file) {
    FILE *PUB_FILE = fopen(key_file, "r");
    EVP_PKEY *tmp = PEM_read_PUBKEY(PUB_FILE, NULL, NULL, NULL);
    fclose(PUB_FILE);
    if(tmp != NULL) {
        jwt->key = tmp;
        return 1;
    }else {
        return -1;
    }
}

int 
jwt_load_priv(libjwt_t *jwt, const char *key_file) {
    FILE *KEY_FILE = fopen(key_file, "r");
    EVP_PKEY *tmp = PEM_read_PrivateKey(KEY_FILE, NULL, NULL, NULL);
    fclose(KEY_FILE);
    if(tmp != NULL) {
        jwt->key = tmp;
        return 1;
    }else {
        return -1;
    }
}

char *jwt_sign(libjwt_t *jwt, const char *header, const char *claim) {
    unsigned int headers_hash_len = base64_encoded_length(strlen(header));
    unsigned char headers_hash[headers_hash_len];
    unsigned int claims_hash_len = base64_encoded_length(strlen(claim));
    unsigned char claims_hash[claims_hash_len];
    str_t headers_src = {
        .data = header,
        .len = strlen(header)
    };
    str_t headers_dst = {
        .data = headers_hash,
        .len = headers_hash_len
    };
    str_t claims_src = {
        .data = claim,
        .len = strlen(claim)
    };
    str_t claims_dst = {
        .data = claims_hash,
        .len = claims_hash_len
    };

    encode_base64url(&headers_dst, &headers_src);
    encode_base64url(&claims_dst, &claims_src);
    
    unsigned char sign[256];
    unsigned int sign_len = 256;
    
    unsigned int sign_hash_len = base64_encoded_length(256);
    unsigned char sign_hash[sign_hash_len];
    str_t sign_src = {
        .data = sign,
        .len = sign_len
    };
    
    int ret = token_sign(&headers_dst, &claims_dst, &sign_src, jwt->key);
    if (ret != 1) {
        perror("sign fail\n");
        return NULL;
    }
    
    str_t sign_dst = {
        .data = sign_hash,
        .len = sign_hash_len
    };
    encode_base64url(&sign_dst, &sign_src);
    
    unsigned int token_len = headers_dst.len + claims_dst.len + sign_dst.len + 2;
    char *token = malloc(token_len + 1);
    int cursor = 0;
    memcpy(token + cursor, headers_dst.data, headers_dst.len);
    cursor += headers_dst.len;

    memcpy(token + cursor, ".", 1);
    cursor++;

    memcpy(token + cursor, claims_dst.data, claims_dst.len);
    cursor += claims_dst.len;

    memcpy(token + cursor, ".", 1);
    cursor++;

    memcpy(token + cursor, sign_dst.data, sign_dst.len);
    cursor += sign_dst.len;
    token[token_len] = '\0';
    
    return token;
}

int 
jwt_verify(libjwt_t *jwt, const char *token) {
    str_t bearer_token = {
        .data = token,
        .len = strlen(token)
    };
    
    return token_verify(&bearer_token, jwt->key);
}

static int
BN_to_base64_str(BIGNUM *bn, char *out) {
    str_t dst = {
        .data = out,
        .len = 0
    };
    int src_len = BN_num_bytes(bn);
    char src_data[src_len];
    BN_bn2bin(bn, src_data);
    str_t src = {
        .data = src_data,
        .len = src_len
    };
    encode_base64url(&dst, &src);
    out[dst.len] = '\0';
}

inline static void
make_jwk_common(cJSON *jwk_json, const char *kty, char *kid, libjwt_alg_t *rsa_alg) {
    /* kty, key type, required */
    cJSON_AddStringToObject(jwk_json, "kty", kty);
    
    /* alg, algorithm, optional */
    if(LIKELY(kid != NULL)) {
        cJSON_AddStringToObject(jwk_json, "kid", kid);
    }
    
    /* alg, optional */
    if(!rsa_alg) {
        cJSON_AddStringToObject(jwk_json, "alg", ALG_STR[*rsa_alg]);
    }
}

inline static void
make_jwk_public(cJSON *jwk_json, RSA *rsa_pk) {
    /* n, Modulus, required */
    BIGNUM *n = rsa_pk->n;
    char n_hash[BN_base64_encoded_length(n) + 1];
    BN_to_base64_str(n, n_hash);
    cJSON_AddStringToObject(jwk_json, "n", n_hash);
    
    /* e, Exponent, required */
    BIGNUM *e = rsa_pk->e;
    char e_hash[BN_base64_encoded_length(n) + 1];
    BN_to_base64_str(e, e_hash);
    cJSON_AddStringToObject(jwk_json, "e", e_hash);
}

inline static void
make_jwk_private(cJSON *jwk_json, RSA *rsa_pk) {
    /* d, Private Exponent, required */
    BIGNUM *d = rsa_pk->d;
    char d_hash[BN_base64_encoded_length(d) + 1];
    BN_to_base64_str(d, d_hash);
    cJSON_AddStringToObject(jwk_json, "d", d_hash);
    
    /* p, First Prime Factor, required */
    BIGNUM *p = rsa_pk->p;
    char p_hash[BN_base64_encoded_length(p) + 1];
    BN_to_base64_str(p, p_hash);
    cJSON_AddStringToObject(jwk_json, "p", p_hash);
    
    /* q, Second Prime Factor */
    BIGNUM *q = rsa_pk->q;
    char q_hash[BN_base64_encoded_length(q) + 1];
    BN_to_base64_str(q, q_hash);
    cJSON_AddStringToObject(jwk_json, "q", q_hash);
}

char *
rsa_read_public_key(FILE *pk, char *kid, libjwt_alg_t *rsa_alg) {
    RSA *rsa_pk = PEM_read_RSA_PUBKEY(pk, NULL, NULL, NULL);
    if(UNLIKELY(!rsa_pk)) {
        return NULL;
    }
    cJSON *jwk_json = cJSON_CreateObject();
    make_jwk_common(jwk_json, "RSA", kid, rsa_alg);
    make_jwk_public(jwk_json, rsa_pk);
    
    char *res = cJSON_PrintUnformatted(jwk_json);
    cJSON_Delete(jwk_json);
    return res;
}

char *
rsa_read_private_key(FILE *pk, char *kid, libjwt_alg_t *rsa_alg) {
    RSA *rsa_pk = PEM_read_RSAPrivateKey(pk, NULL, NULL, NULL);
    if(UNLIKELY(!rsa_pk)) {
        return NULL;
    }
    cJSON *jwk_json = cJSON_CreateObject();
    make_jwk_common(jwk_json, "RSA", kid, rsa_alg);
    make_jwk_public(jwk_json, rsa_pk);
    
    
}

