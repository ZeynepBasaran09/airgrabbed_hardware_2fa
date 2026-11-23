# Air-Gapped Hardware 2FA (Challenge-Response HSM Prototype)

A dual-microcontroller hardware authentication prototype implementing an isolated **Hardware Security Module (HSM)** architecture using an **Arduino Uno (ATmega328P)** and an **ESP32**. Written in pure C without dynamic heap allocation (`String`) or external cryptographic dependencies on the HSM side.

## Security Architecture

* **Air-Gapped Key Isolation:** The 256-bit `SECRET_KEY` resides solely inside the Arduino Uno's flash memory and is never exposed over external network interfaces or debug serial ports.
* **Replay Attack Protection:** The ESP32 gateway generates a cryptographically secure 128-bit random `nonce` per session via its hardware True Random Number Generator (`esp_fill_random`).
* **Zero-Dependency Bare-Metal HMAC-SHA256:** Custom C implementation of SHA-256 and HMAC-SHA256 running directly on ATmega328P.
* **Timing Attack Mitigation:** Signature verification on the ESP32 uses a constant-time XOR comparison (`constant_time_compare`) to prevent side-channel latency leaks.
* **Physical Presence Verification:** A 10k potentiometer connected to `ADC0` (`A0`) acts as a hardware interlock; the HSM refuses to sign challenges (`ERR:LOCKED`) unless physically unlocked.
* **Resistorless Level-Shifted UART (Open-Drain):** Safe 5V-to-3.3V UART communication without a voltage divider by driving the Arduino TX line (`PB3`) strictly in Open-Drain mode (`OUTPUT LOW` for `0`, `INPUT` Hi-Z for `1`) while the ESP32 holds the line at `3.3V` via internal pull-up.

## Pinout & Wiring

| Arduino Uno | ESP32 | Function |
| :--- | :--- | :--- |
| `GND` | `GND` | Common Ground |
| `Pin 10 (PB2)` | `GPIO 17 (TX2)` | Challenge (`CHAL:<32-hex>`) |
| `Pin 11 (PB3)` | `GPIO 16 (RX2)` | Open-Drain Response (`RESP:<64-hex>`) |
| `A0` (`5V` / `GND`) | — | 10k Potentiometer (Physical Presence Lock) |
| — | `GPIO 21 (D21)` | Active Buzzer (Audio Feedback) |

## Protocol Flow

1. Gateway triggers authentication (`auth` via `115200` baud Serial Monitor).
2. ESP32 sends `CHAL:<16-byte-hex-nonce>\n` over `Serial2` (`9600` baud).
3. Arduino verifies physical presence (`ADC0 >= 200`), computes `HMAC-SHA256(SECRET_KEY, nonce)`, and replies with `RESP:<32-byte-hex-mac>\n`.
4. ESP32 validates the MAC in constant time and triggers audio/serial confirmation.

> **Note:** The symmetric key hardcoded in the source files is a demonstration placeholder. Rotate keys before any real deployment.

## Roadmap

* [ ] Python CLI login client (`pyserial`) for host-side 2FA enforcement
* [ ] ADC range-based physical combination lock & failed-attempt lockout timer
