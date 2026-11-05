# HSM PKCS#11 Provider Library

Cryptoki v2.40 shared library provider enabling standard tools (such as OpenSC pkcs11-tool, OpenSSL pkcs11-provider, and OpenSSH) to perform hardware-isolated cryptographic operations using connected HSM USB keys.

## Features
- **Cryptoki v2.40 Standard Compliant**: Integrates directly with OpenSC (`pkcs11-tool`), OpenSSL (`pkcs11-provider`), OpenSSH (`ssh-add -s`), and GnuPG.
- **AT ASCII Serial Transport**: Clean, line-buffered serial transport communicating over CDC-ACM UART (`115200 8N1`).
- **Cryptographic Mechanisms**:
  - `CKM_EC_KEY_PAIR_GEN`: Hardware-isolated secp256r1 (NIST P-256) keypair generation via CryptoCell CC310.
  - `CKM_ECDSA` & `CKM_ECDSA_SHA256`: Hardware ECDSA signing.
  - `C_GenerateRandom`: TRNG random number generation.
- **Cross-Platform**: Builds on macOS (`.dylib`), Linux (`.so`), and Windows (`.dll`).
- **Auto-Discovery & Serial Targeting**:
  - Auto-discovers connected USB HSM devices via CDC-ACM UART interfaces (`VID 0x1209`, `PID 0x0001`, Protocol ID `0x0002`).
  - Prioritizes device nodes corresponding to the dedicated AT data communication channel (e.g., macOS `/dev/tty.usbmodem*3`) over diagnostic console logger interfaces (Protocol ID `0x0001`).
  - Supports `NRF52840_HSM_SERIAL` targeting `/dev/tty.usbmodem<SERIAL>3`.
  - Supports `NRF52840_HSM_PORT` override for explicit device paths or virtual pseudo-terminal (PTY) simulation.
  - Supports `NRF52840_HSM_DEBUG=1` for detailed serial protocol traffic traces.

---

## Directory Structure
```text
nrf52840-hsm-libpkcs11/
├── CMakeLists.txt
├── Makefile
├── README.md
├── include/
│   ├── pkcs11/
│   │   ├── cryptoki.h
│   │   ├── pkcs11.h
│   │   ├── pkcs11t.h
│   │   └── pkcs11f.h
│   └── nrf52840_p11_internal.h
├── src/
│   ├── p11_general.c
│   ├── p11_slot.c
│   ├── p11_session.c
│   ├── p11_object.c
│   ├── p11_crypto.c
│   └── transport/
│       ├── at_client.h
│       ├── at_client.c
│       ├── serial_transport.h
│       ├── serial_posix.c
│       └── serial_win32.c
└── tests/
    └── test_p11_mock.c
```

---

## Building
```bash
# Using Make
make build

# Or using CMake directly
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The resulting dynamic library will be located at:
- macOS: `build/libnrf52840_pkcs11.dylib`
- Linux: `build/libnrf52840_pkcs11.so`

---

## Testing
```bash
# Run unit tests
make test

# Or run the test executable directly
./build/test_p11_mock

# Test with virtual mock HSM PTY
NRF52840_HSM_PORT=/tmp/mock-hsm-pty ./build/test_p11_mock
```

---

## Integration with Standard Tools

### OpenSC `pkcs11-tool`
```bash
# List slots and mechanisms
pkcs11-tool --module build/libnrf52840_pkcs11.dylib -L
pkcs11-tool --module build/libnrf52840_pkcs11.dylib -M

# Generate EC P-256 keypair
pkcs11-tool --module build/libnrf52840_pkcs11.dylib --login --pin 123456 \
  --keypairgen --key-type EC:prime256v1 --label "MyP256Key" --id 01

# Sign pre-hashed SHA-256 digest
openssl dgst -sha256 -binary data.txt > digest.bin
pkcs11-tool --module build/libnrf52840_pkcs11.dylib --login --pin 123456 \
  --sign --id 01 --mechanism ECDSA --input-file digest.bin --output-file sig.raw
```

### OpenSSH
```bash
# Add HSM key to ssh-agent
ssh-add -s build/libnrf52840_pkcs11.dylib
```
