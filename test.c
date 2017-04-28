#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "cJSON.h"
#include "libJWT.h"

typedef struct {
    size_t len;
    u_char *data;
} str_t;

#define base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define base64_decoded_length(len)  (((len + 3) / 4) * 3)

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

static intptr_t
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

intptr_t
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

intptr_t
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

void
encode_base64(str_t *dst, str_t *src) {
    static u_char basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    encode_base64_internal(dst, src, basis64, 1);
}

void
encode_base64url(str_t *dst, str_t *src) {
    static u_char basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    encode_base64_internal(dst, src, basis64, 0);
}

intptr_t
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

intptr_t
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

int main(int argc, char **argv) {
    printf("Hello World!\n");

    FILE *test1 = fopen("./server.pub", "r");
    FILE *test2 = fopen("./server.pub", "r");

    rsa_read_public_key(test2, NULL, ALG_RS256);
    
    /* open key files */
    FILE *KEY_FILE = fopen("./server.key", "r");
    FILE *PEM_FILE = fopen("./server.pem", "r");
    FILE *PUB_FILE = fopen("./server.pub", "r");
   

    OpenSSL_add_all_algorithms();

    EVP_PKEY *private_key = NULL;
    EVP_PKEY *tmp_pk = PEM_read_PrivateKey(KEY_FILE, NULL, NULL, NULL);
    if (tmp_pk == NULL) {
        printf("read private key fail\n");
        exit(-1);
    } else {
        printf("read private key successful\n");
    }
    private_key = tmp_pk;
    tmp_pk = NULL;

    X509 *cert = PEM_read_X509(PEM_FILE, NULL, NULL, NULL);
    if (cert == NULL) {
        printf("read X509 fail\n");
        exit(-1);
    } else {
        printf("read X509 successful\n");
    }
    EVP_PKEY *public_key_1 = X509_get_pubkey(cert);
    if (public_key_1 == NULL) {
        printf("get_pubkey fail\n");
        exit(-1);
    } else {
        printf("get public key 1 successful\n");
    }

    EVP_PKEY *public_key_2 = NULL;
    EVP_PKEY *tmp_pubkey2 = PEM_read_PUBKEY(PUB_FILE, &public_key_2, NULL, NULL);
    if (tmp_pubkey2 == NULL) {
        printf("read public key 2 fail\n");
        exit(-1);
    } else {
        printf("read public key 2 successful\n");
    }
    public_key_2 = tmp_pubkey2;
    
    RSA *priv_key = EVP_PKEY_get1_RSA(private_key);
    printf("BN_num_bits(priv_key->n): %d\n", BN_num_bits(priv_key->n));
    printf("BN_num_bytes(priv_key->n): %d\n", BN_num_bytes(priv_key->n));
    printf("priv_key->p: %p\n", priv_key->p);
    
    RSA *pub_key2 = EVP_PKEY_get1_RSA(public_key_2);
    printf("pub_key2->p: %p\n", pub_key2->p);
    
    
    
    BIO *bio2 = BIO_new_fp(stdout, BIO_NOCLOSE);
    BN_print(bio2, pub_key2->e);
    BIO_free(bio2);
    
    int e_len = BN_num_bytes(pub_key2->e);
    char e_tmp[e_len];
    BN_bn2bin(pub_key2->e, e_tmp);
    
    str_t e_src = {
        .data = e_tmp,
        .len = e_len
    };
    unsigned int e_hash_len = base64_encoded_length(e_len);
    char e_hash[e_hash_len];
    str_t e_dst = {
        .data = e_hash,
        .len = e_hash_len
    };
    
    encode_base64url(&e_dst, &e_src);
    printf("e_hash: %.*s\n", e_dst.len, e_dst.data);

    /* fake payload */
    unsigned char pay_load[32];
    for (int i = 0; i < 32; i++) {
        pay_load[i] = 'a';
    }
    unsigned char sign1[257];
    unsigned int len1;
    unsigned char sign2[257];
    unsigned int len2;
    unsigned char sign3[257];
    unsigned int len3;

    /* JWT headers */
    cJSON *headers = cJSON_CreateObject();
    cJSON_AddStringToObject(headers, "typ", "JWT");
    cJSON_AddStringToObject(headers, "alg", "RS256");
    char *headers_str = cJSON_PrintUnformatted(headers);
    printf("headers: %s\n", headers_str);

    /* JWT Claim Set */
    cJSON *claims = cJSON_CreateObject();
    cJSON_AddStringToObject(claims, "iss", "auth.wisetv.com.cn");
    cJSON_AddStringToObject(claims, "sub", "dawei");
    cJSON_AddStringToObject(claims, "aud", "message.wisetv.com.cn");
    cJSON_AddNumberToObject(claims, "exp", 1415387315);
    cJSON_AddNumberToObject(claims, "nbf", 1415387015);
    cJSON_AddNumberToObject(claims, "iat", 1415387015);
    cJSON_AddStringToObject(claims, "jti", "tYJCO1c6cnyy7kAn0c7rKPgbV1H1bFws");

    cJSON *access = cJSON_CreateArray();
    cJSON *email = cJSON_CreateObject();
    cJSON_AddStringToObject(email, "type", "email");
    cJSON_AddNumberToObject(email, "privilege", 4);
    cJSON_AddItemToArray(access, email);

    cJSON_AddItemToObject(claims, "access", access);
    char *claims_str = cJSON_PrintUnformatted(claims);
    printf("claims: %s\n", claims_str);

    /* Signature */
    unsigned int headers_hash_len = base64_encoded_length(strlen(headers_str));
    unsigned char headers_hash[headers_hash_len];
    unsigned int claims_hash_len = base64_encoded_length(strlen(claims_str));
    unsigned char claims_hash[claims_hash_len];
    str_t headers_src = {
        .data = headers_str,
        .len = strlen(headers_str)
    };
    str_t headers_dst = {
        .data = headers_hash,
        .len = headers_hash_len
    };
    str_t claims_src = {
        .data = claims_str,
        .len = strlen(claims_str)
    };
    str_t claims_dst = {
        .data = claims_hash,
        .len = claims_hash_len
    };

    encode_base64url(&headers_dst, &headers_src);
    encode_base64url(&claims_dst, &claims_src);

    printf("headers: %.*s\n", headers_dst.len, headers_dst.data);
    printf("claims: %.*s\n", claims_dst.len, claims_dst.data);

    unsigned char sign[256];
    unsigned int sign_len = 256;
    
    unsigned int sign_hash_len = base64_encoded_length(256);
    unsigned char sign_hash[sign_hash_len];
    str_t sign_src = {
        .data = sign,
        .len = sign_len
    };
    
    int ret = token_sign(&headers_dst, &claims_dst, &sign_src, private_key);
    if (ret != 1) {
        printf("sign fail\n");
        exit(-1);
    }
    
    str_t sign_dst = {
        .data = sign_hash,
        .len = sign_hash_len
    };
    encode_base64url(&sign_dst, &sign_src);
    printf("sign: %.*s\n", sign_dst.len, sign_dst.data);
    

    /* token */
    unsigned int token_len = headers_dst.len + claims_dst.len + sign_dst.len + 2;
    unsigned char token[token_len];
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
    str_t bearer_token = {
        .data = token,
        .len = token_len
    };

    printf("token: %.*s\n", bearer_token.len, bearer_token.data);

    ret = token_verify(&bearer_token, private_key);
    if (ret == 1) {
        printf("RSA_verify with KEY_RSA successful\n");
    }

    ret = token_verify(&bearer_token, public_key_1);
    if (ret == 1) {
        printf("RSA_verify with PEM_RSA successful\n");
    }

    ret = token_verify(&bearer_token, public_key_2);
    if (ret == 1) {
        printf("RSA_verify with PUB_RSA successful\n");
    }
    
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_private(bio, private_key, 4, NULL);
    BIO_free(bio);

    /* release resources */
    free(headers_str);
    free(claims_str);
    cJSON_Delete(headers);
    cJSON_Delete(claims);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key_1);
    EVP_PKEY_free(public_key_2);
    X509_free(cert);
    fclose(KEY_FILE);
    fclose(PEM_FILE);
    fclose(PUB_FILE);
    EVP_cleanup();
}
