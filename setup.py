#!/usr/bin/env python3
from setuptools import setup

setup(
    name="StegaMe",
    version="1.0",
    description="Encrypts or decrypts STDIN to STDOUT using steganography.",
    license="GPLv3",
    author="z0noxz",
    author_email="z0noxz@mail.com",
    url="https://github.com/z0noxz/stegame",
    classifiers=[
        "Development Status :: 1.0 - Beta",
        "Intedent Audience :: Anybody",
        "License :: Free Software :: GPLv3",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Topic :: Encryption :: Steganography"
    ],
    requires=[
        "os",
        "sys",
        "select",
        "hashlib",
        "random",
        "argparse",
        "getpass",
        "curses",
        "enum",
        "io",
        "PIL",
        "Crypto",
        "Crypto.Cipher"
    ],
    scripts=[
        "bin/stegame"
    ],
    packages=[
        "stegame"
    ]
)
