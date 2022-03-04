#include <arm_cmse.h>
#include <stdio.h>
#include <string.h>
#include "NuMicro.h"                      /* Device header */

#define NEXT_BOOT_BASE  0x10040000
#define JUMP_HERE       0xe7fee7ff      /* Instruction Code of "B ." */

/* typedef for NonSecure callback functions */
typedef __NONSECURE_CALL int32_t (*NonSecure_funcptr)(uint32_t);

#define FMC_SECURE_BOUNDARY     0x40000UL
#define NON_SECURE_BASE         (0x10000000ul+FMC_SECURE_BOUNDARY) /* Base Address of Non-secure Image */
#define SRAM_SECURE_BOUNDARY    0x10000UL
#define NON_SECURE_SRAM_BASE    (0x30000000UL+SRAM_SECURE_BOUNDARY)/* Base Address of Non-secure SRAM */

void CRPT_IRQHandler(void);
void SYS_Init(void);
void UART0_Init(void);
void Boot_Init(uint32_t u32BootBase);

extern uint32_t g_u32IsSHA_done;
extern uint32_t g_u32IsAES_done;
extern struct Sign sign_val;

extern int32_t calc_size(int algorithm);
extern void crypto_hash(char plain[], uint32_t digest[], int algorithm, int32_t size);
extern void crypto_symmetric(uint8_t input[], uint8_t output[], int size, int algorithm, int EncDec);
extern int32_t crypto_ecc_genKey(char prvk[], char pubk_x[], char pubk_y[], int algorithm, int size);
extern void crypto_ecc_init(char msg[], int algorithm);
extern int32_t crypto_ecc_sign(char prvk[], char rand[], char sign_r[], char sign_s[]);
extern int32_t crypto_ecc_verify(char pubk_x[], char pubk_y[], char sign_r[], char sign_s[]);

/*----------------------------------------------------------------------------
  Secure functions exported to NonSecure application
  Must place in Non-secure Callable
 *----------------------------------------------------------------------------*/
__NONSECURE_ENTRY
void crypto_hash_call(char plain[], uint32_t digest[], int algorithm) {
		int32_t size = calc_size(algorithm);
		crypto_hash(plain, digest, algorithm, size);
}

__NONSECURE_ENTRY
void crypto_symmetric_call(uint8_t input[], uint8_t output[], int algorithm, int EncDec) {
		int32_t size = calc_size(algorithm);
		crypto_symmetric(input, output, size, algorithm, EncDec);
}

__NONSECURE_ENTRY
int32_t crypto_ecc_genKey_call(char prvk[], char pubk_x[], char pubk_y[], int algorithm) {
		int32_t size = calc_size(algorithm);
		int32_t ret = crypto_ecc_genKey(prvk, pubk_x, pubk_y, algorithm, size);
		return ret;
}

__NONSECURE_ENTRY
void crypto_ecc_sign_init_call(char msg[], int algorithm) {
		crypto_ecc_init(msg, algorithm);
}

__NONSECURE_ENTRY
int32_t crypto_ecc_sign_call(char prvk[], char rand[], char sign_r[], char sign_s[]) {
		int32_t ret = crypto_ecc_sign(prvk, rand, sign_r, sign_s);
		return ret;
}

__NONSECURE_ENTRY
int32_t crypto_ecc_verify_call(char pubk_x[], char pubk_y[], char sign_r[], char sign_s[]) {
		int32_t ret = crypto_ecc_verify(pubk_x, pubk_y, sign_r, sign_s);
		return ret;
}
/*----------------------------------------------------------------------------
  Main function
 *----------------------------------------------------------------------------*/
int main(void)
{
    SYS_UnlockReg();
    SYS_Init();

    /* UART0 is configured as Nonsecure for debug in both secure and nonsecure region */
    UART0_Init();

    /* Set PA to non-secure */
    SCU_SET_IONSSET(SCU_IONSSET_PA_Msk);

    /* SCB_NS.VTOR points to the Non-secure vector table base address. */
    SCB_NS->VTOR = NON_SECURE_BASE;

    /* 1st Entry in the vector table is the Non-secure Main Stack Pointer. */
    __TZ_set_MSP_NS(*((uint32_t *)SCB_NS->VTOR));      /* Set up MSP in Non-secure code */

    do
    {
        if(SCB->AIRCR & SCB_AIRCR_BFHFNMINS_Msk)
        {
            printf("by Non-secure code.\n");
        }
        else
        {
            printf("by secure code.\n");
        }

        //PA10_NS = 1;
        Boot_Init(NEXT_BOOT_BASE);

    }
    while(1);
}

/*----------------------------------------------------------------------------
    Boot_Init function is used to jump to next boot code.
 *----------------------------------------------------------------------------*/
void Boot_Init(uint32_t u32BootBase)
{
    NonSecure_funcptr fp;

    /* SCB_NS.VTOR points to the Non-secure vector table base address. */
    SCB_NS->VTOR = u32BootBase;

    /* 1st Entry in the vector table is the Non-secure Main Stack Pointer. */
    __TZ_set_MSP_NS(*((uint32_t *)SCB_NS->VTOR));      /* Set up MSP in Non-secure code */

    /* 2nd entry contains the address of the Reset_Handler (CMSIS-CORE) function */
    fp = ((NonSecure_funcptr)(*(((uint32_t *)SCB_NS->VTOR) + 1)));

    /* Clear the LSB of the function address to indicate the function-call
       will cause a state switch from Secure to Non-secure */
    fp = cmse_nsfptr_create(fp);

    /* Check if the Reset_Handler address is in Non-secure space */
    if(cmse_is_nsfptr(fp) && (((uint32_t)fp & 0xf0000000) == 0x10000000))
    {
        printf("Execute non-secure code ...\n");
        fp(0); /* Non-secure function call */
    }
    else
    {
        /* Something went wrong */
        printf("No code in non-secure region!\n");
        printf("CPU will halted at non-secure state\n");

        /* Set nonsecure MSP in nonsecure region */
        __TZ_set_MSP_NS(NON_SECURE_SRAM_BASE + 512);

        /* Try to halted in non-secure state (SRAM) */
        M32(NON_SECURE_SRAM_BASE) = JUMP_HERE;
        fp = (NonSecure_funcptr)(NON_SECURE_SRAM_BASE + 1);
        fp(0);

        while(1);
    }
}


void CRPT_IRQHandler()
{
    if(SHA_GET_INT_FLAG(CRPT))
    {
        g_u32IsSHA_done = 1;
        SHA_CLR_INT_FLAG(CRPT);
    }
		
		if(AES_GET_INT_FLAG(CRPT))
    {
        g_u32IsAES_done = 1;
        AES_CLR_INT_FLAG(CRPT);
    }
}

void SYS_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init System Clock                                                                                       */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Enable HIRC clock */
    CLK_EnableXtalRC(CLK_PWRCTL_HIRCEN_Msk);

    /* Wait for HIRC clock ready */
    CLK_WaitClockReady(CLK_STATUS_HIRCSTB_Msk);

    /* Set PLL frequency */
    CLK->PLLCTL = CLK_PLLCTL_128MHz_HIRC;

    /* Waiting for PLL stable */
    CLK_WaitClockReady(CLK_STATUS_PLLSTB_Msk);

    /* Select HCLK clock source as PLL and HCLK source divider as 2 */
    CLK_SetHCLK(CLK_CLKSEL0_HCLKSEL_PLL, CLK_CLKDIV0_HCLK(2));

    /* Set SysTick source to HCLK/2*/
    CLK_SetSysTickClockSrc(CLK_CLKSEL0_STCLKSEL_HCLK_DIV2);
    
    /* Enable UART module clock */
    CLK_EnableModuleClock(UART0_MODULE);
    CLK_SetModuleClock(UART0_MODULE, CLK_CLKSEL1_UART0SEL_HIRC, CLK_CLKDIV0_UART0(1));

    /* Enable CRYPTO module clock */
    CLK_EnableModuleClock(CRPT_MODULE);

    /*---------------------------------------------------------------------------------------------------------*/
    /* Init I/O Multi-function                                                                                 */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Set multi-function pins for UART0 RXD and TXD */
    SYS->GPB_MFPH = (SYS->GPB_MFPH & (~(UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk))) | UART0_RXD_PB12 | UART0_TXD_PB13;
}

void UART0_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART                                                                                               */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Reset IP */

    /* Configure UART0 and set UART0 Baudrate */
    UART0_NS->BAUD = UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(__HIRC, 115200);
    UART0_NS->LINE = UART_WORD_LEN_8 | UART_PARITY_NONE | UART_STOP_BIT_1;
}
