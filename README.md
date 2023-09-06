# Chaes
A Simple AES256-GCM+ChaCha20_Poly1305 encryptor and decryptor.
__ __

<br>
<br>

# ⚠️ Extra Note ⚠️
This repository/code and [Chaeslib](https://pypi.org/project/Chaeslib/) are in __NO__ way associated with "[Chaes malware](https://www.bleepingcomputer.com/news/security/chaes-malware-now-uses-google-chrome-devtools-protocol-to-steal-data/)" as reported on by [Bleeping computer](https://www.bleepingcomputer.com/). I made this repository and projects and named them this way first. If anyone is interested, I chose the name becuase of "AES" and "ChaCha" are the encryption methods I have used and meshed together. I also do find it kind of funny that th emalware uses the same name.
> If to much confussion happens, I will have no issues changing the name of this project

<br>
<br>

# About
Chaes is my implementation of combining the encryption methods of AES-GCM and ChaCha20_Poly1305. I would use [Deoxys](https://sites.google.com/view/deoxyscipher) too but I can't find anything for it for python. Not even pycryptodome or cryptography has it yet, only in `Rust` and `Go` can I really find it. But rest assured, when it does become available for python, I am going to try and add it to my concoction of encryptions for chaeslib.

Want to use this encryption for your own projects? Now you can! with [Chaeslib](https://pypi.org/project/Chaeslib/).
__ __

![2023-02-16_12-54](https://user-images.githubusercontent.com/45724082/219472726-90df44d2-f7a9-4d57-9dec-e3eff13d5fad.png)

<br />
<br />

# Changes & Updates
> 5/14/23

<br />

Added:

* Squashed some bugs. If checks when checking to see if a file was encrypted or not and if the file has ".locked" or not will now work like it should.
* Added a new feature to allow you to encrypt data using an already generated key. Instead of generating a new one each time you want to encrypt some data.
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
