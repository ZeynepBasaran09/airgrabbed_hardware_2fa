#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "mbedtls/md.h"
#include "esp_system.h"
#include "driver/gpio.h"

#define RX2_PIN 16
#define TX2_PIN 17
#define BUZZER_PIN 21

static const uint8_t VERIFIER_KEY[32] = {
    0x4A, 0x8F, 0x1C, 0x92, 0xE3, 0x7B, 0x05, 0xD4,
    0x61, 0xA9, 0x3E, 0xF0, 0x88, 0x2C, 0x57, 0xB1,
    0x9D, 0x44, 0x10, 0xE8, 0x73, 0x2A, 0xC6, 0x5F,
    0x0B, 0x81, 0xD9, 0x34, 0x6E, 0xA2, 0x17, 0x95
};

static bool constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}

static uint8_t hex_to_nibble(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    return 0;
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t expected_bytes) {
    if (strlen(hex) != expected_bytes * 2) return false;
    for (size_t i = 0; i < expected_bytes; ++i) {
        out[i] = (uint8_t)((hex_to_nibble(hex[i * 2]) << 4) | hex_to_nibble(hex[i * 2 + 1]));
    }
    return true;
}

static void bytes_to_hex(const uint8_t *data, size_t len, char *out_hex) {
    static const char hex_chars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; ++i) {
        out_hex[i * 2]     = hex_chars[(data[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    out_hex[len * 2] = '\0';
}

static void beep_success(void) {
    digitalWrite(BUZZER_PIN, HIGH);
    delay(80);
    digitalWrite(BUZZER_PIN, LOW);
}

static void beep_fail(void) {
    for (int i = 0; i < 3; ++i) {
        digitalWrite(BUZZER_PIN, HIGH);
        delay(100);
        digitalWrite(BUZZER_PIN, LOW);
        delay(80);
    }
}

static void compute_expected_hmac(const uint8_t challenge[16], uint8_t out_mac[32]) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, VERIFIER_KEY, sizeof(VERIFIER_KEY));
    mbedtls_md_hmac_update(&ctx, challenge, 16);
    mbedtls_md_hmac_finish(&ctx, out_mac);
    mbedtls_md_free(&ctx);
}

static void run_auth_cycle(void) {
    uint8_t nonce[16];
    uint8_t expected_mac[32];
    uint8_t received_mac[32];
    char chal_hex[33];
    char tx_frame[42];
    char rx_line[96];

    esp_fill_random(nonce, sizeof(nonce));
    bytes_to_hex(nonce, 16, chal_hex);
    compute_expected_hmac(nonce, expected_mac);

    while (Serial2.available()) {
        (void)Serial2.read();
    }

    snprintf(tx_frame, sizeof(tx_frame), "CHAL:%s\n", chal_hex);

    unsigned long start_us = micros();
    /* Baytlar arasına 1 ms koyarak Arduino yazılım RX döngüsünün sıfır kayıpla okumasını sağla */
    for (size_t i = 0; tx_frame[i] != '\0'; ++i) {
        Serial2.write((uint8_t)tx_frame[i]);
        delay(1);
    }
    Serial.printf("\n[GATEWAY] Challenge Gonderildi -> %s\n", chal_hex);

    /* Maksimum 1000 ms yanıt bekle */
    size_t idx = 0;
    unsigned long start_ms = millis();
    while (millis() - start_ms < 1000) {
        if (Serial2.available()) {
            char c = (char)Serial2.read();
            if (c == '\r') continue;
            if (c == '\n') {
                break;
            }
            if (idx < sizeof(rx_line) - 1) {
                rx_line[idx++] = c;
            }
        }
    }
    rx_line[idx] = '\0';
    unsigned long elapsed_us = micros() - start_us;

    if (idx == 0) {
        Serial.println("[HATA] HSM Zaman Asimi! Baglantilari kontrol et.");
        beep_fail();
        return;
    }

    if (strcmp(rx_line, "ERR:LOCKED") == 0) {
        Serial.println("[RED] Fiziksel Onay Kapali! Potansiyometreyi cevirin.");
        beep_fail();
        return;
    }

    if (strncmp(rx_line, "RESP:", 5) != 0) {
        Serial.printf("[HATA] Gecersiz cerceve formati: %s\n", rx_line);
        beep_fail();
        return;
    }

    if (!hex_to_bytes(rx_line + 5, received_mac, 32)) {
        Serial.println("[HATA] Bozuk HMAC uzunlugu.");
        beep_fail();
        return;
    }

    if (constant_time_compare(expected_mac, received_mac, 32)) {
        Serial.printf("[ONAY] Kriptografik 2FA Basarili! (Sure: %lu us)\n", elapsed_us);
        beep_success();
    } else {
        Serial.printf("[ALARM] Sahte Imza / Anahtar Uyusmazligi! (Sure: %lu us)\n", elapsed_us);
        beep_fail();
    }
}

void setup(void) {
    Serial.begin(115200);
    pinMode(BUZZER_PIN, OUTPUT);
    digitalWrite(BUZZER_PIN, LOW);

    /* UART matrisini bozmadan RX2 (GPIO 16) üzerinde dahili pull-up'ı aktif et */
    Serial2.begin(9600, SERIAL_8N1, RX2_PIN, TX2_PIN);
    gpio_pullup_en((gpio_num_t)RX2_PIN);

    delay(1000);
    Serial.println("=== Donanimsal 2FA Dogrulayici (Pure C) Hazir ===");
    Serial.println("Dogrulama baslatmak icin Seri Monitor'den 'auth' yazip Enter'a basin.");
}

void loop(void) {
    static char cmd_buf[32];
    static size_t cmd_idx = 0;

    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\r') continue;
        if (c == '\n') {
            cmd_buf[cmd_idx] = '\0';
            if (strcmp(cmd_buf, "auth") == 0 || strcmp(cmd_buf, "AUTH") == 0) {
                run_auth_cycle();
            }
            cmd_idx = 0;
        } else if (cmd_idx < sizeof(cmd_buf) - 1) {
            cmd_buf[cmd_idx++] = c;
        } else {
            cmd_idx = 0;
        }
    }
}