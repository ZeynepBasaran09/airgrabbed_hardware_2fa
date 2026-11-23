#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <util/delay.h>

/* ATmega328P Pin Eşleşmeleri:
 * Digital Pin 10 -> PB2 (RX - ESP32 TX2'den gelir)
 * Digital Pin 11 -> PB3 (Open-Drain TX - ESP32 RX2'ye gider)
 * Analog  Pin A0 -> ADC0 (10k Potansiyometre)
 */
#define RX_BIT PB2
#define TX_BIT PB3
#define BIT_DELAY_US 104

/* 256-bit (32 byte) Gizli Anahtar - Dışarıya asla aktarılmaz */
static const uint8_t SECRET_KEY[32] = {
    0x4A, 0x8F, 0x1C, 0x92, 0xE3, 0x7B, 0x05, 0xD4,
    0x61, 0xA9, 0x3E, 0xF0, 0x88, 0x2C, 0x57, 0xB1,
    0x9D, 0x44, 0x10, 0xE8, 0x73, 0x2A, 0xC6, 0x5F,
    0x0B, 0x81, 0xD9, 0x34, 0x6E, 0xA2, 0x17, 0x95
};

/* --- SAF C SHA-256 VE HMAC-SHA256 GERÇEKLEŞTİRİMİ --- */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
} sha256_ctx_t;

static const uint32_t k_sha256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    for (uint8_t i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    }
    for (uint8_t i = 16; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (uint8_t i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k_sha256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[]) {
    size_t i = ctx->datalen;
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56) ctx->data[i++] = 0x00;

    ctx->bitlen += ctx->datalen * 8;
    for (uint8_t j = 0; j < 8; ++j) {
        ctx->data[63 - j] = (uint8_t)(ctx->bitlen >> (j * 8));
    }
    sha256_transform(ctx, ctx->data);

    for (uint8_t j = 0; j < 4; ++j) {
        for (uint8_t k = 0; k < 8; ++k) {
            hash[j + k * 4] = (uint8_t)((ctx->state[k] >> (24 - j * 8)) & 0xFF);
        }
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out_mac[32]) {
    uint8_t k_ipad[64], k_opad[64], inner_hash[32];
    sha256_ctx_t ctx;

    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5C, 64);

    for (size_t i = 0; i < key_len && i < 64; ++i) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, msg, msg_len);
    sha256_final(&ctx, inner_hash);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, out_mac);
}

/* --- BARE-METAL AVR DONANIM VE OPEN-DRAIN UART FONKSİYONLARI --- */
static void hw_init(void) {
    /* Pin 10 (PB2) Giriş, Pin 11 (PB3) Open-Drain (PORTB=0, DDRB=0 -> Hi-Z) */
    DDRB &= ~((1 << RX_BIT) | (1 << TX_BIT));
    PORTB &= ~((1 << RX_BIT) | (1 << TX_BIT));

    /* ADC0 (A0) Başlatma: AVcc referans, prescaler 128 */
    ADMUX = (1 << REFS0);
    ADCSRA = (1 << ADEN) | (1 << ADPS2) | (1 << ADPS1) | (1 << ADPS0);
}

static uint16_t adc_read_a0(void) {
    ADCSRA |= (1 << ADSC);
    while (ADCSRA & (1 << ADSC));
    return ADC;
}

static void uart_od_write_byte(uint8_t b) {
    PORTB &= ~(1 << TX_BIT);
    cli();

    /* Start Bit (0V) */
    DDRB |= (1 << TX_BIT);
    _delay_us(BIT_DELAY_US);

    /* 8 Veri Biti (LSB first) */
    for (uint8_t i = 0; i < 8; ++i) {
        if ((b >> i) & 0x01) {
            DDRB &= ~(1 << TX_BIT); /* Lojik 1: Serbest bırak (3.3V) */
        } else {
            DDRB |= (1 << TX_BIT);  /* Lojik 0: GND'ye çek (0V) */
        }
        _delay_us(BIT_DELAY_US);
    }

    /* Stop Bit (Serbest bırak) */
    DDRB &= ~(1 << TX_BIT);
    _delay_us(BIT_DELAY_US);
    sei();
}

static void uart_od_print(const char *str) {
    while (*str) {
        uart_od_write_byte((uint8_t)(*str++));
    }
}

static uint8_t uart_rx_read_byte(void) {
    uint8_t val = 0;
    /* Start bit (LOW) bekle */
    while (PINB & (1 << RX_BIT));

    cli();
    _delay_us(BIT_DELAY_US / 2); /* Bit ortasına hizalan */
    for (uint8_t i = 0; i < 8; ++i) {
        _delay_us(BIT_DELAY_US);
        if (PINB & (1 << RX_BIT)) {
            val |= (1 << i);
        }
    }
    _delay_us(BIT_DELAY_US); /* Stop bit süresi */
    sei();
    return val;
}

static uint8_t hex_to_nibble(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    return 0;
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t byte_len) {
    for (size_t i = 0; i < byte_len; ++i) {
        out[i] = (uint8_t)((hex_to_nibble(hex[i * 2]) << 4) | hex_to_nibble(hex[i * 2 + 1]));
    }
}

static void bytes_to_hex(const uint8_t *data, size_t len, char *out_hex) {
    static const char hex_chars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; ++i) {
        out_hex[i * 2]     = hex_chars[(data[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    out_hex[len * 2] = '\0';
}

static void handle_frame(const char *line) {
    if (strncmp(line, "CHAL:", 5) != 0) return;

    /* Fiziksel onay kontrolü (Potansiyometre A0 < 200 ise kilitli) */
    if (adc_read_a0() < 200) {
        uart_od_print("ERR:LOCKED\n");
        return;
    }

    const char *chal_hex = line + 5;
    if (strlen(chal_hex) != 32) {
        uart_od_print("ERR:LEN\n");
        return;
    }

    uint8_t challenge[16];
    uint8_t mac[32];
    char resp_buf[72]; /* "RESP:" (5) + 64 hex + "\n\0" (2) */

    hex_to_bytes(chal_hex, challenge, 16);
    hmac_sha256(SECRET_KEY, 32, challenge, 16, mac);

    memcpy(resp_buf, "RESP:", 5);
    bytes_to_hex(mac, 32, resp_buf + 5);
    resp_buf[69] = '\n';
    resp_buf[70] = '\0';

    uart_od_print(resp_buf);
}

void setup(void) {
    hw_init();
}

void loop(void) {
    static char rx_buf[64];
    static uint8_t idx = 0;

    char c = (char)uart_rx_read_byte();
    if (c == '\r') return;

    if (c == '\n') {
        rx_buf[idx] = '\0';
        handle_frame(rx_buf);
        idx = 0;
    } else if (idx < sizeof(rx_buf) - 1) {
        rx_buf[idx++] = c;
    } else {
        idx = 0; /* Taşma koruması */
    }
}