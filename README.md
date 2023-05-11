# Chaes
A Simple AES256-GCM+ChaCha20_Poly1305 encryptor and decryptor.
__ __

<br />

# About
Chaes is my implementation of combining the encryption methods of AES-GCM and ChaCha20_Poly1305. I would use [Deoxys](https://sites.google.com/view/deoxyscipher) too but I can't find anything for it for python. Not even pycryptodome or cryptography has it yet, only in `Rust` and `Go` can I really find it. But rest assured, when it does become available for python, I am going to try and add it to my concoction of encryptions here.

Want to use this encryption for your own projects? Now you can! with [Chaeslib](https://pypi.org/project/Chaeslib/).
__ __

![2023-02-16_12-54](https://user-images.githubusercontent.com/45724082/219472726-90df44d2-f7a9-4d57-9dec-e3eff13d5fad.png)

<br />
<br />

# Changes & Updates
> 5/1/23

<br />

Added:
* Functionality to encrypt and decrypt files.
* Handling reading and parsing large files are a bit faster now. (encrypting & decrypting the data isn't any faster yet)
> Works with images, .zip archives, and .tar.gz archives.
__ __

<br />
<br />

# Todo
> [] - Add/implement Deoxys
__ __

<br />
<br />

# Installation
```bash
git clone https://github.com/therealOri/Chaes.git
cd Chaes
virtualenv chaENV
source chaENV/bin/activate
pip install -r requirements.txt
python Chaes.py
```
> If you don't have `virtualenv` you can install it via pip

`pip install virtualenv`
__ __


<br />
<br />
<br />

# Support  |  Buy me a coffee <3
(God knows I need one xD)

Donate to me here:
> - Don't have Cashapp? [Sign Up](https://cash.app/app/TKWGCRT)

![image](https://user-images.githubusercontent.com/45724082/158000721-33c00c3e-68bb-4ee3-a2ae-aefa549cfb33.png)
