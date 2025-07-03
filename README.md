# Secure Command Uplink

This project simulates a secure uplink communication system using MQTT with TLS encryption, AES-GCM message encryption, and HMAC verification. Commands like `reboot`, `shutdown`, and `rotate` can be sent securely to a simulated satellite.

---

## Features

- MQTT communication with TLS mutual authentication  
- AES-GCM encrypted payloads with timestamp  
- HMAC verification for message integrity  
- Replay attack protection (reject messages older than 5 seconds)  
- Simulated command execution on subscriber side

---

## Setup Instructions

### Prerequisites

- Python 3.8+  
- Mosquitto MQTT broker (version 2.0+) with TLS support  
- `paho-mqtt` Python library (`pip install paho-mqtt`)  
- OpenSSL for generating certificates

### Certificates

Make sure the `certs/` directory contains:

- `ca.crt` and `ca.key` (Certificate Authority files)  
- `server.crt` and `server.key` (Broker certificate and key)  
- `client.crt` and `client.key` (Client certificate and key)

---

## How to Run

### Start Mosquitto Broker

```bash
mosquitto -c mosquitto_tls.conf

