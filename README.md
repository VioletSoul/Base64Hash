# Base64+ Encoder

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Tkinter](https://img.shields.io/badge/Tkinter-3776AB?style=flat&logo=python&logoColor=white)
![Base64](https://img.shields.io/badge/Base64-✓-yellow)
![Cipher](https://img.shields.io/badge/Cipher-✓-blue)
![Hashing](https://img.shields.io/badge/Hashing-✓-purple)
![Thread Safety](https://img.shields.io/badge/Thread%20Safe-✓-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue)
[![Stars](https://img.shields.io/github/stars/VioletSoul/Base64Hash.svg?style=social)](https://github.com/VioletSoul/Base64Hash)
[![Last Commit](https://img.shields.io/github/last-commit/VioletSoul/Base64Hash.svg)](https://github.com/VioletSoul/Base64Hash/commits/main)

**Base64+ Encoder** is a convenient and functional graphical application written in Python using Tkinter, designed for encoding, encrypting, and hashing text. The program supports various algorithms and provides a user-friendly tabbed interface for different tasks.

---

## Key Features

- **Encoding and Encryption**
  - Base64 (standard and URL-safe)
  - Caesar cipher supporting Russian and English alphabets (including the letter Ё)
  - Atbash cipher
  - XOR cipher with a user-defined key
  - Deprecated algorithms MD5 and SHA1 (optional)

- **Base64 Decoding**  
  Enter Base64 code and instantly decode it with result display.

- **Hashing**
  - SHA3-256
  - BLAKE2b

  Each hashing algorithm has its own tab with an input field and automatic hash output.

- **Thread Safety and Responsiveness**  
  All computations run in separate threads to ensure a smooth and responsive interface without freezes.

---

## Interface

The application is organized into tabs:

1. **Ciphers and Encoding** – text input, cipher parameters, and display of encoding and encryption results.
2. **Base64 Decoding** – two windows: Base64 input and decoded text output.
3. **SHA3-256 Hashing** – text input and SHA3-256 hash display.
4. **BLAKE2b Hashing** – text input and BLAKE2b hash display.

Each tab features clear labels and convenient multi-line scrollable text fields.

---

## Requirements

- Python 3.6 or higher
- Standard library modules: `tkinter`, `hashlib`, `base64`, `threading`

---

## Running the Application

1. Download or clone the repository.
2. Run the script: base64_gen.py


---

## Usage Example

- Enter text on the **Ciphers and Encoding** tab, adjust parameters (XOR key, Caesar shift), and results will update automatically.
- On the **Base64 Decoding** tab, paste a Base64 string - the decoded text will appear instantly.
- The **SHA3-256 Hashing** and **BLAKE2b Hashing** tabs allow quick generation of hashes from any input text.

---

## License

MIT License

---

## Contact

If you have any questions or suggestions, please open an issue in the repository.

---

**Base64+ Encoder** is a simple yet powerful tool for working with text and encodings, ideal for learning, testing, and everyday use.
