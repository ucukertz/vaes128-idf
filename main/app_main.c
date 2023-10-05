#include <stdio.h>
#include <sdkconfig.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_system.h>
#include <esp_spi_flash.h>
#include <esp_log.h>

#include "vaes128cbc.h"

static const char* TAG = "VAES128CBC";

void app_main(void)
{
  uint8_t* msgk = (uint8_t*)"exmplemsgkey"; // Doesn't need to be 16 bytes like regular AES128
  uint8_t* siv = (uint8_t*)"examplesiv"; // Doesn't need to be the same length as msgk

  size_t msgk_len = strlen((char*)msgk);
  size_t siv_len = strlen((char*)siv);
  ESP_LOGI(TAG, "MSGK: %.*s len %u", msgk_len, msgk, msgk_len);
  ESP_LOGI(TAG, "SIV: %.*s len %u", siv_len, siv, siv_len);

  vaes128cbc_skeys_t vaesk = vaes128cbc_setkeys(siv, siv_len, msgk, msgk_len);
  uint8_t* plaintext = (uint8_t*)"Hello!";
  char* encr;
  uint8_t* decr;
  size_t decr_len;

  vaes128cbc_enc_hstr(vaesk, plaintext, strlen((char*)plaintext), &encr);
  ESP_LOGI(TAG, "%s", encr);

  while (1) {
    vaes128cbc_dec_hstr(vaesk, encr, strlen(encr), &decr, &decr_len);
    ESP_LOGI(TAG, "%.*s", decr_len, decr);
    free(encr);
    vTaskDelay(pdMS_TO_TICKS(1000));
    vaes128cbc_enc_hstr(vaesk, decr, decr_len, &encr);
    ESP_LOGI(TAG, "%s", encr);
    free(decr);
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
