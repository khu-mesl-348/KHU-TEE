#include <stdio.h>
#include <string.h>
#include "M2351.h"
#include "secure_platform.h"

volatile uint32_t g_u32IsSHA_done = 0;
volatile uint32_t g_u32IsAES_done = 0;

uint32_t g_au32MyAESKey[8] =
{
    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f
};

uint32_t g_au32MyAESIV[4] =
{
    0x00000000, 0x00000000, 0x00000000, 0x00000000
};

int32_t calc_size(int algorithm) {
		int32_t size;
	
		switch (algorithm) {
			case SHA160:
				size = (160 / 8);
				break;
			case SHA224:
				size = (224 / 8);
				break;
			case SHA256:
				size = (256 / 8);
				break;
			case SHA384:
				size = (384 / 8);
				break;
			case SHA512:
				size = (512 / 8);
				break;
			case AES128:
				size = (128 / 8);
				break;
			case AES192:
				size = (192 / 8);
				break;
			case AES256:
				size = (256 / 8);
				break;
			case ECC_P_192:
				size = 192;
				break;
			case ECC_P_224:
				size = 224;
				break;
			case ECC_P_256:
				size = 256;
				break;
			case ECC_P_384:
				size = 384;
				break;
			case ECC_P_521:
				size = 521;
				break;
		}
		
		return size;
}

uint8_t Byte2Char(uint8_t c)
{
    if(c < 10)
        return (c + '0');
    if(c < 16)
        return (c - 10 + 'a');

    return 0;
}

void hw_acc_disable() {
		SHA_DISABLE_INT(CRPT);
		AES_DISABLE_INT(CRPT);
		ECC_DISABLE_INT(CRPT);
		NVIC_DisableIRQ(CRPT_IRQn);
}

void crypto_hash(char plain[], uint32_t digest[], int algorithm, int32_t size) {
		hw_acc_disable();
		
		uint32_t output[size];
		
		NVIC_EnableIRQ(CRPT_IRQn);
		SHA_ENABLE_INT(CRPT);
		
		switch (algorithm) {
				case SHA160:
					XSHA_Open(XCRPT, SHA_MODE_SHA1, SHA_IN_OUT_SWAP, 0);
					break;
				case SHA224:
					XSHA_Open(XCRPT, SHA_MODE_SHA224, SHA_IN_OUT_SWAP, 0);
					break;
				case SHA256:
					XSHA_Open(XCRPT, SHA_MODE_SHA256, SHA_IN_OUT_SWAP, 0);
					break;
				case SHA384:
					XSHA_Open(XCRPT, SHA_MODE_SHA384, SHA_IN_OUT_SWAP, 0);
					break;
				case SHA512:
					XSHA_Open(XCRPT, SHA_MODE_SHA512, SHA_IN_OUT_SWAP, 0);
					break;
		}
		
		XSHA_SetDMATransfer(XCRPT, (uint32_t)&plain[0], strlen(plain));
		XSHA_Start(XCRPT, CRYPTO_DMA_ONE_SHOT);

		g_u32IsSHA_done = 0;
		XSHA_Read(XCRPT, output);
		while(g_u32IsSHA_done == 0) {}
			
		for (int i = 0; i < size; i++) {
				digest[i] = output[i];
		}
}

void crypto_symmetric(uint8_t input[], uint8_t output[], int size, int algorithm, int EncDec) {
		hw_acc_disable();
	
		NVIC_EnableIRQ(CRPT_IRQn);
    AES_ENABLE_INT(CRPT);
	
		uint32_t KEY_SIZE;
		switch (algorithm) {
				case AES128:
					KEY_SIZE = AES_KEY_SIZE_128;
					break;
				case AES192:
					KEY_SIZE = AES_KEY_SIZE_192;
					break;
				case AES256:
					KEY_SIZE = AES_KEY_SIZE_256;
					break;
		}
		
		XAES_Open(XCRPT, 0, EncDec, AES_MODE_ECB, KEY_SIZE, AES_IN_OUT_SWAP);
		XAES_SetKey(XCRPT, 0, g_au32MyAESKey, KEY_SIZE);
    XAES_SetInitVect(XCRPT, 0, g_au32MyAESIV);
    XAES_SetDMATransfer(XCRPT, 0, (uint32_t)input, (uint32_t)output, size);

    g_u32IsAES_done = 0;
    XAES_Start(XCRPT, 0, CRYPTO_DMA_ONE_SHOT);
    while(g_u32IsAES_done == 0) {}
}

int32_t crypto_ecc_genKey(char prvk[], char pubk_x[], char pubk_y[], int algorithm, int size) {
		hw_acc_disable();
	
		int32_t ret;	
		int32_t i, j;
		E_ECC_CURVE curve;
		uint8_t au8r[size / 8];
		int32_t i32NBits = size;
		XTRNG_T rng;
		
		ECC_ENABLE_INT(CRPT);
		XTRNG_RandomInit(&rng, XTRNG_PRNG | XTRNG_LIRC32K);
	
		XTRNG_Random(&rng, au8r, i32NBits / 8);
	
		for (i = 0, j = 0; i < i32NBits / 8; i++) {
				prvk[j++] = Byte2Char(au8r[i] & 0xf );
				prvk[j++] = Byte2Char(au8r[i] >> 4);
		}
		prvk[j] = 0;
		
		switch (algorithm) {
				case ECC_P_192:
					curve = CURVE_P_192;
					break;
				case ECC_P_224:
					curve = CURVE_P_224;
					break;
				case ECC_P_256:
					curve = CURVE_P_256;
					break;
				case ECC_P_384:
					curve = CURVE_P_384;
					break;
				case ECC_P_521:
					curve = CURVE_P_521;
					break;
		}
		
		if (XECC_IsPrivateKeyValid(XCRPT, curve, prvk)) {
				if (XECC_GeneratePublicKey(XCRPT, curve, prvk, pubk_x, pubk_y) < 0) {
						ret = ECC_KEYGEN_FAIL_PUBK;
				}
				else {
						ret = ECC_KEYGEN_SUCCESS;
				}
				ret = ECC_KEYGEN_SUCCESS;
		}
		else { // private key is not valid.
				ret = ECC_KEYGEN_FAIL_PRVK;
		}

		return ret;
}

char ecc_msg[];
int ecc_algorithm;

void crypto_ecc_init(char msg[], int algorithm) {
		strcpy(ecc_msg, msg);
		ecc_algorithm = algorithm;
}

int32_t crypto_ecc_sign(char prvk[], char rand[], char sign_r[], char sign_s[]) {
		hw_acc_disable();
	
		int size = calc_size(ecc_algorithm);
		int32_t ret;	
		int32_t i, j;
		E_ECC_CURVE curve;
		uint8_t au8r[size / 8];
		int32_t i32NBits = size;
		XTRNG_T rng;
		
		ECC_ENABLE_INT(CRPT);
		
		XTRNG_RandomInit(&rng, XTRNG_PRNG | XTRNG_LIRC32K);
	
		XTRNG_Random(&rng, au8r, i32NBits / 8);
	
		for (i = 0, j = 0; i < i32NBits / 8; i++) {
				rand[j++] = Byte2Char(au8r[i] & 0xf );
				rand[j++] = Byte2Char(au8r[i] >> 4);
		}
		rand[j] = 0;
		
		switch (ecc_algorithm) {
				case ECC_P_192:
					curve = CURVE_P_192;
					break;
				case ECC_P_224:
					curve = CURVE_P_224;
					break;
				case ECC_P_256:
					curve = CURVE_P_256;
					break;
				case ECC_P_384:
					curve = CURVE_P_384;
					break;
				case ECC_P_521:
					curve = CURVE_P_521;
					break;
		}
		
		if (XECC_GenerateSignature(XCRPT, curve, ecc_msg, prvk, rand, sign_r, sign_s) < 0) {
				ret = ECC_SIGN_FAIL;
		}
		else {
				ret = ECC_SIGN_SUCCESS;
		}
		
		return ret;
}

int32_t crypto_ecc_verify(char pubk_x[], char pubk_y[], char sign_r[], char sign_s[]) {
		hw_acc_disable();
	
		int32_t ret;	
		E_ECC_CURVE curve;		
		ECC_ENABLE_INT(CRPT);
	
		switch (ecc_algorithm) {
				case ECC_P_192:
					curve = CURVE_P_192;
					break;
				case ECC_P_224:
					curve = CURVE_P_224;
					break;
				case ECC_P_256:
					curve = CURVE_P_256;
					break;
				case ECC_P_384:
					curve = CURVE_P_384;
					break;
				case ECC_P_521:
					curve = CURVE_P_521;
					break;
		}
		
		if (XECC_VerifySignature(XCRPT, curve, ecc_msg, pubk_x, pubk_y, sign_r, sign_s) < 0) {
				ret = ECC_VERIFY_FAIL;
		}
		else {
				ret = ECC_VERIFY_SUCCESS;
		}
		
		return ret;
}