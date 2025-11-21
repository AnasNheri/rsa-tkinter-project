# RSA Encryption & Digital Signature with Tkinter

## Description
This project demonstrates the use of **RSA asymmetric encryption** and **digital signatures** using Python.  
It provides a **simple graphical interface** with Tkinter to:  

- Encrypt and decrypt messages using RSA keys.  
- Generate digital signatures to ensure message authenticity and integrity.  
- Verify signatures to detect any message modification.  

This project is ideal for learning **cryptography basics** and how to integrate it with a user-friendly GUI.

---

## Features
- **RSA Key Generation**: Automatically generates a 2048-bit private and public key pair.  
- **Message Encryption**: Encrypt messages with the public key.  
- **Message Decryption**: Decrypt messages with the private key.  
- **Digital Signature**: Sign messages using the private key to guarantee authenticity.  
- **Signature Verification**: Verify the integrity of messages using the public key.  
- **Graphical User Interface**: Simple Tkinter interface for easy interaction.

---

## Screenshots
*(Add screenshots of your Tkinter interface here for better presentation)*

---

## Installation

1. **Clone the repository**:

```bash
git clone https://github.com/AnasNHERI/rsa-tkinter-project.git
cd rsa-tkinter-project
pip install cryptography
python rsa_tkinter.py
