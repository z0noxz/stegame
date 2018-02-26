StegaMe: Encrypts or decrypts STDIN to STDOUT using steganography.
==================================================================

Contact
-------
* Author: z0noxz
* Source: https://github.com/z0noxz/stegame
* Email: z0noxz@mail.com

Description
-----------
This program is a steganographical tool with encryption using a passphrase.
It takes the STDIN and either encrypts it into a given image and outputs to
STDOUT or decrypts out to STDOUT.

The tool scrambles the bits, encrypts them and stores them in the least
significant bits of the colors in each pixel. The pixels that aren't affected
gets random bits as noise to hide the fact that anything has been changed.

How to use
----------

Prerequisites:

	python3
	python3-setuptools

Prerequisites (python3 modules):

	os
	sys
	select
	hashlib
	random
	argparse
	getpass
	curses
	enum
	io
	PIL
	Crypto
	Crypto.Cipher

Install it (using python3-setuptools):

	git clone https://github.com/z0noxz/stegame
	cd stegame
	./setup.py install

Encrypt a secret message and hide it inside photo.png:

	stegame photo.png < secret.txt > encrypted.png

Decrypt and retrive the message from encrypted.png:

	stegame -d < encrypted.png > decrypted.txt

