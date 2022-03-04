#include <arm_cmse.h>
#include <string.h>
#include "NuMicro.h"                      /* Device header */
#include "secure_platform.h"

void dump_hex(uint8_t *buf, int32_t len);

/*----------------------------------------------------------------------------
  NonSecure Callable Functions from Secure Region
 *----------------------------------------------------------------------------*/
extern void crypto_hash_call(char plain[], uint32_t digest[], int algorithm);
extern void crypto_symmetric_call(uint8_t input[], uint8_t output[], int algorithm, int EncDec);
extern int32_t crypto_ecc_genKey_call(char prvk[], char pubk_x[], char pubk_y[], int algorithm);

extern void crypto_ecc_sign_init_call(char msg[], int algorithm);
extern int32_t crypto_ecc_sign_call(char prvk[], char rand[], char sign_r[], char sign_s[]);
extern int32_t crypto_ecc_verify_call(char pubk_x[], char pubk_y[], char sign_r[], char sign_s[]);

/*----------------------------------------------------------------------------
  Main function
 *----------------------------------------------------------------------------*/

int main(void)
{
	  __attribute__((aligned(4))) char plain[] = "123456789ABCdef";
	
    printf("\n");
    printf("+---------------------------------------------+\n");
    printf("|    Nonsecure code is running ... SHA256     |\n");
    printf("+---------------------------------------------+\n");

		printf("plain: %s\n", plain);
		
		int32_t digest_len = (256 / 8);
		uint32_t digest[digest_len];
		memset(digest, 0, digest_len);
	
		crypto_hash_call(plain, digest, SHA256);
			
		printf("digest: ");
		dump_hex((uint8_t *)digest, digest_len);
	
	  printf("\n");
    printf("+---------------------------------------------+\n");
    printf("|    Nonsecure code is running ... AES128     |\n");
    printf("+---------------------------------------------+\n");
		
		__attribute__((aligned(4))) uint8_t input[] = {
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
		};
		
		printf("plain: ");
		dump_hex(input, sizeof(input));
		
		int32_t enc_len = sizeof(input)/sizeof(input[0]);
		uint8_t enc[enc_len];
		memset(enc, 0, enc_len);
		
		crypto_symmetric_call(input, enc, AES128, ENCRYPTION);
		
		printf("enc: ");
		dump_hex(enc, enc_len);
		
		int32_t dec_len = sizeof(input);
		uint8_t dec[dec_len];
		memset(dec, 0, dec_len);
		
		crypto_symmetric_call(enc, dec, AES128, DECRYPTION);
		
		printf("dec: ");
		dump_hex(dec, dec_len);
		
		printf("\n");
    printf("+---------------------------------------------+\n");
    printf("|    Nonsecure code is running ... ECC P-256  |\n");
    printf("+---------------------------------------------+\n");
		
		char prvk[68], rand[68];
		char pubk_x[68], pubk_y[68];
		char sign_r[68], sign_s[68];
		char msg[] = "Hello MESL! I'm KHU-TEE.";
		
		int32_t keygen = crypto_ecc_genKey_call(prvk, pubk_x, pubk_y, ECC_P_256);
		if (keygen  == ECC_KEYGEN_SUCCESS) {
				printf("Private key = %s\n", prvk);
				printf("Public Qx   = %s\n", pubk_x);
				printf("Public Qy   = %s\n", pubk_y);
		}
		else if (keygen  == ECC_KEYGEN_FAIL_PRVK) {
				printf("Private key is not valid.\n");
		}
		else if (keygen  == ECC_KEYGEN_FAIL_PUBK) {
				printf("Public key generation failed.\n");
		}
		
		crypto_ecc_sign_init_call(msg, ECC_P_256);

		int32_t sign = crypto_ecc_sign_call(prvk, rand, sign_r, sign_s);
		if (sign == ECC_SIGN_SUCCESS) {
				printf("message = %s\n", msg);
				printf("sign_r  = %s\n", sign_r);
				printf("sign_s  = %s\n", sign_s);
		}
		else {
				printf("ECC signature generation failed.\n");
		}
				
		int32_t verify = crypto_ecc_verify_call(pubk_x, pubk_y, sign_r, sign_s);
		if (verify == ECC_VERIFY_SUCCESS) {
				printf("ECC digital signature verification OK!!\n");
		}
		else {
				printf("ECC digital signature verification failed.\n");
		}
				
    while(1);
}

void dump_hex(uint8_t *buf, int32_t len)
{
		int32_t i = 0;
	
		while (len > 0) {
				printf("%02X", buf[i++]);
				len--;
		}
		printf("\n");
}