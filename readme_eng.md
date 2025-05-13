# Encoder

A versatile application for encoding and hashing text.

---

## Description

This is a simple yet powerful Python graphical application that allows you to quickly obtain various types of encodings and hashes from the input text. The program supports a wide range of algorithms, including modern and classical ones, and lets you customize parameters for certain ciphers.

---

## Key Features

- **Encoding:**
  - Base64 (standard and URL-safe)
  - Caesar cipher with customizable shift
  - Atbash cipher
  - XOR cipher with customizable key

- **Hashing:**
  - Modern algorithms SHA3-256 and BLAKE2b
  - Deprecated MD5 and SHA1 (with warnings about insecurity)

- **Support for Russian and English alphabets:**
  - Including the letter Ё/ё, which is rarely supported in similar programs

- **Dynamic result updates:**
  - Encoding and hashing results appear in real-time as you type

- **User-friendly and clear interface:**
  - Color-coded headers, algorithm names, results, and warnings

- **Input validation and error handling:**
  - The program informs users about invalid parameters and remains stable

- **Multithreading:**
  - Calculations run in a separate thread to keep the interface responsive

---

## Who is this program for?

- Developers needing to quickly verify various encodings and hashes
- Students and educators studying cryptography and encoding
- Anyone interested in encryption and experimenting with different algorithms
- Users who want to convert text into various formats without complex commands or setup

---

## How to use

1. Launch the program.
2. Enter text into the input field at the top.
3. Configure parameters:
   - XOR key (integer from 0 to 255)
   - Caesar cipher shift (integer)
   - Check the box if you want to see deprecated algorithms (MD5, SHA1)
4. The results will automatically appear in the output area below.
5. Pay attention to any warnings displayed.

---

## Technical details

- Written in Python 3 using the standard `tkinter` library for the GUI.
- Utilizes built-in modules `base64`, `hashlib`, and `codecs`.
- Properly supports Russian language, including the letter Ё.
- Uses multithreading to keep the interface smooth and responsive.

---

## License

This code and program are freely available for any use. The author is not responsible for how the program is used.

---

## Contact

For questions or suggestions, please contact the author via the project repository (if available) or leave feedback.

---

Thank you for using the program! We hope it will be useful and convenient for your tasks.
