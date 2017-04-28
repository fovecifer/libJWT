#ifndef LIBJWT_H
#define LIBJWT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/evp.h>

typedef enum {
    ALG_NONE,
    ALG_RS256,
    ALG_RS384,
    ALG_RS512
} libjwt_alg_t;

static const char *ALG_STR[] = {
    "none", "RS256", "RS384", "RS512"
};

typedef int (*set_jwk_t)(char *jwk_str);
typedef int (*set_alg_t)(libjwt_alg_t a);
typedef int (*set_payload_t)(char *payload_str);
typedef char *(*sign_t)();
typedef int (*verify_t)(char *jwt_str);
    
typedef struct {
    EVP_PKEY *key;
    libjwt_alg_t alg;
    char *payload;
    set_jwk_t *set_jwt;
    set_alg_t *set_alg;
    set_payload_t *set_payload;
    sign_t *sign;
    verify_t *verify;
} libjwt_t;

extern libjwt_t *jwt_create();
extern void jwt_release(libjwt_t *jwt);

/* read JWK string from RSA private key file, caller need free the string */
extern char *rsa_read_private_key(FILE *pk, char *kid, libjwt_alg_t *rsa_alg);
/* read JWK string from RSA public key file, caller need free the string */
extern char *rsa_read_public_key(FILE *pk, char *kid, libjwt_alg_t *rsa_alg);

#ifdef __cplusplus
}
#endif

#endif /* LIBJWT_H */

