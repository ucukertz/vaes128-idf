#ifndef __VAES128CBC_H
#define __VAES128CBC_H

#include <stdio.h>
#include <string.h>

#include <esp_system.h>
#include <esp_log.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <mbedtls/aes.h>
#include <mbedtls/md.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  VAES128_BLOCKSZ = 16, // 16 * 8 bit = 128
};

typedef enum {
  VAES128CBC_OK,
  VAES128CBC_ERR_WRONG_LEN,
  VAES128CBC_ERR_INVALID_HEXSTR,
  VAES128CBC_ERR_DECRYPT_FAIL,
  VAES128CBC_ERR_ENCRYPT_FAIL,
} vaes128cbc_err_t;

// VAES128 CBC key structure
typedef struct {
  uint8_t static_iv[VAES128_BLOCKSZ];
  uint8_t siv_len;
  uint8_t static_msgk[VAES128_BLOCKSZ];
  uint8_t smsgk_len;
} vaes128cbc_skeys_t;

vaes128cbc_skeys_t vaes128cbc_setkeys(uint8_t* siv, uint8_t siv_len, uint8_t* smsgk, uint8_t smsgk_len);
vaes128cbc_err_t vaes128cbc_enc(vaes128cbc_skeys_t vaesk, uint8_t* buf, size_t len, uint8_t** cipher, size_t* cipher_len);
vaes128cbc_err_t vaes128cbc_enc_hstr(vaes128cbc_skeys_t vaesk, uint8_t* buf, size_t len, char** cipher_hstr);
vaes128cbc_err_t vaes128cbc_dec(vaes128cbc_skeys_t vaesk, uint8_t* cipher, size_t cipher_len, uint8_t** buf, size_t* len);
vaes128cbc_err_t vaes128cbc_dec_hstr(vaes128cbc_skeys_t vaesk, char* cipher_hstr, size_t chstr_len, uint8_t** buf, size_t* len);

void vaes128cbc_byte2hstr(uint8_t* buf, size_t len, char* out);
vaes128cbc_err_t vaes128cbc_hstr2byte(char* hstr, size_t len, uint8_t* out);

#ifdef __cplusplus
}
#endif

#endif // __VAES128CBC_H
