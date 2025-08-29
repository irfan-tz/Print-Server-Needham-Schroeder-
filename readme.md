
# Print Server (Needham–Schroeder Style) 
  
This repository implements a KDC, a multi-threaded Print Server (PrnSrv) and a Client (Alice) in C. The client authenticates to the KDC using a passphrase-derived long-term key (PBKDF2). The KDC issues a signed ticket and a session key (AES-GCM). The client then authenticates to the Print Server using the ticket and sends a file (text or image). The Print Server converts it to PDF and returns the encrypted PDF. OpenSSL (libcrypto) is used for AES-GCM / PBKDF2. All three programs are multithreaded.

---

## Files
- `kdc.c` — KDC server implementation.
- `prnsrv.c` — Print server implementation.
- `client.c` — Client implementation.
- `Makefile` — Makefile (compile targets).
- `run.sh` — example run script.

---

## Requirements
On Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y build-essential libssl-dev libhpdf-dev tcpdump tshark wireshark
```
(If you prefer image conversion via CLI, also install `img2pdf` or `imagemagick`.)

---

## Build
Using the provided Makefile:
```bash
make all
```
Or compile manually:
```bash
gcc -o kdc kdc.c -lcrypto -lpthread
gcc -o prnsrv prnsrv.c -lcrypto -lhpdf -lpthread
gcc -o client client.c -lcrypto
```

---

## How to run (single-machine test)
Start each program in a separate terminal (or `tmux`/`screen`).

1. Start the KDC (default port **9001**):
```bash
./kdc
```

2. Start the Print Server (default port **9010**):
```bash
./prnsrv
```

3. Create a sample text file:
```bash
echo "Hello from Alice" > sample.txt
```

4. Run the client:
```bash
# Usage: ./client <USERNAME> <PASSWORD> <FILENAME>
./client ALICE password sample.txt
```

Default users and sample password are initialized in the KDC source for now. See `kdc.c` for details.

---

## Protocol overview (quick)
1. Client → KDC: username + client-nonce.
2. KDC ↔ Client: challenge-response using the user's long-term key (derived from passphrase).
3. KDC → Client: encrypted blob containing session key (K_AP) and a ticket encrypted for the Print Server.
4. Client → Print Server: ticket + client nonce; Print Server verifies ticket and performs challenge-response under K_AP.
5. Client → Print Server: encrypted file (AES-GCM under K_AP).
6. Print Server: converts to PDF and returns encrypted PDF (AES-GCM).

---

## Converting files to PDF
- The sample `prnsrv.c` contains a text-to-PDF converter using libharu.
- To add image support, either:
  - call `img2pdf` / ImageMagick from the server, or
  - embed images into PDF via a library.

Example quick conversion command (if using system call in the server):
```c
system("img2pdf input.jpg -o output.pdf");
```

---  

## Limitations & notes
- **Fixed salt & demo passwords**: PBKDF2 uses a fixed salt and demo passwords are seeded in the KDC for convenience. Replace with per-user random salts and a secure user store for production.
- **Ticket replay**: The demo shows basic expiry but does not maintain a replay cache. For production, store used nonces/tickets or use sequence numbers.
- **Logging**: Servers print nonces / IVs and debug info to stdout for grading. This is insecure in production.
- **File types**: The sample code currently focuses on text-to-PDF. Extend to support images if required.

---

