#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""StegaMe.py

This program is a steganographical tool with encryption using a passphrase.
It takes the STDIN and either encrypts it into a given image and outputs to
STDOUT or decrypts out to STDOUT.

The tool scrambles the bits, encrypts them and stores them in the least
significant bits of the colors in each pixel. The pixels that aren't affected
gets random bits as noise to hide the fact that anything has been changed.

Example:
    Encryption of the text 'secret.txt' into the image 'picture.png' that
    generates output to STDOUT which is passed to 'encrypted.png'.

        $ (python) stegame.py picture.png < secret.txt > encrypted.png

    Decryption of the generated image 'encrypted.png' that generates output to
    STDOUT which is passed to 'decrypted.txt', and if all goes well --
    'secret.txt' should have the same content as 'decrypted.txt'.

        $ (python) stegame.py -d < encrypted.png > decrypted.txt

"""

import os
import sys
import select
import hashlib
import random
import argparse
import getpass
import curses

from enum import Enum
from io import BytesIO
from PIL import Image
from Crypto import Random
from Crypto.Cipher import AES


class Utility(object):
    """Utility class used for bit manipulation

    All class methods are static, and used for some sort of bit manipulation
    or retrieval of individual bit from a given byte.

    """

    @staticmethod
    def get_bits(_bytes):
        """Extract all bits from given bytes

        Args:
            _bytes (list): list of bytes

        Yields:
            8 bits for each byte

        """

        for byte in _bytes:
            for i in reversed(range(8)):
                yield (byte >> i) & 1

    @staticmethod
    def get_bytes(bits):
        """Concatenate all bits into list of bytes

        Args:
            bits (list): list of bits

        Yields:
            bytes, 1 for each 8 bits

        """

        byte = 0
        for i, bit in enumerate(bits):
            byte = (byte << 1) | bit
            if (i + 1) % 8 == 0:
                yield byte
                byte = 0

    @staticmethod
    def int_to_bits(_int):
        """Extracts all bits from given integer

        Args:
            _int (int): integer

        Yields:
            32 bits for given integer

        """

        for i in reversed(range(32)):
            yield (_int >> i) & 1

    @staticmethod
    def bits_to_int(bits):
        """Concatenate all bits into an integer

        Args:
            bits (list): list of bits

        Returns:
            int: an integer

        """

        _int = 0
        for bit in bits:
            _int = (_int << 1) | bit
        return _int

    @staticmethod
    def set_bit(byte, bit):
        """Sets the least significant bit of given byte

        Args:
            byte (byte): the byte to be manipulated
            bit (but): the new bit value

        Returns:
            byte: the manipulated byte

        """

        return byte ^ (-bit ^ byte) & 1

    @staticmethod
    def get_bit(byte):
        """Retrieves the least significant bit of given byte

        Args:
            byte (byte): the byte of which the bit will get returned from

        Returns:
            bit: the least significant bit of given byte

        """

        return byte & 1


class Symbol(Enum):
    """Enum class representing types of symbols

    """

    INFO    = 1
    WARNING = 2
    STATUS  = 3
    ERROR   = 4
    SUCCESS = 5


class UI(object):
    """Class for managing UI output

    The class only contains static methods for various UI manipulations

    Attributes:
        verbose (bool): indicator for verbosity
        symbols (list): list of human readable representations of symbols

    """

    verbose = True
    symbols = {
        Symbol.INFO     : "\033[94m[i]\033[0m ",
        Symbol.WARNING  : "\033[96m[!]\033[0m ",
        Symbol.STATUS   : "\033[94m[*]\033[0m ",
        Symbol.ERROR    : "\033[91m[-]\033[0m ",
        Symbol.SUCCESS  : "\033[92m[+]\033[0m ",
    }

    @staticmethod
    def print(text="", end="\n", flush=True, symbol=None):
        """Prints text to STDERR

        The method handles output with or without flushing or ending, and
        has the option to prepend a symbol at the beginning.

        Args:
            text (str): the text to be printed, default: empty
            end (str): the ending of the output, default: new line
            flush (bool): indicator for flushing, default: True
            symbol (Enum:Symbol): prepending symbol, default: None

        Returns:
            int: length of the printed text, including the symbol

        """

        if not UI.verbose:
            return 0
        sys.stderr.write((UI.symbols[symbol] if symbol else "") + text + end)

        if flush:
            sys.stderr.flush()

        # Assume the length of symbols to be 4
        return len(text) + (4 if symbol else 0)

    @staticmethod
    def print_heading(text):
        """Prints a header to STDERR, using UI.print

        """

        UI.print("\033[94m::\033[0m \033[1m%s\033[0m"  % text)

    @staticmethod
    def rewind(length):
        """Rewinds the cursor using a number of '\b' sent to STDERR

        Args:
            length (int): the number of '\b's to be printed

        """

        UI.print("\b" * length, end="", flush=False)

    @staticmethod
    def print_header():
        """Prints a decorative header for aesthetical purpose

        """

        UI.print("\033[38;5;160m"
                 + r" ____  _                   __  __                    "
                 + "\033[0m")
        UI.print("\033[38;5;161m"
                 + r"/ ___|| |_ ___  __ _  __ _|  \/  | ___   _ __  _   _ "
                 + "\033[0m")
        UI.print("\033[38;5;162m"
                 + r"\___ \| __/ _ \/ _` |/ _` | |\/| |/ _ \ | '_ \| | | |"
                 + "\033[0m")
        UI.print("\033[38;5;163m"
                 + r" ___) | ||  __/ (_| | (_| | |  | |  __/_| |_) | |_| |"
                 + "\033[0m")
        UI.print("\033[38;5;164m"
                 + r"|____/ \__\___|\__, |\__,_|_|  |_|\___(_) .__/ \__, |"
                 + "\033[0m")
        UI.print("\033[38;5;165m"
                 + r"               |___/                    |_|    |___/ "
                 + " Created by z0noxz\033[0m")

class ProgressBar(object):
    """Class for managing progress bar output

    Attributes:
        label (str): Prepending label
        length (int): overrides output width if set
        color_width (int): number of colors of terminal
        progress (int): indicator of progress 0 to 100
        last (int): length of last output

    """

    def __init__(self, label=None, length=None, min_width=25):
        """Initialize the progress bar

        Args:
            label (str): Prepending label, default: None
            length (int): output width overrider, default: None
            min_width: minimum width of the label, default: 25

        """

        self.label          = (label + ": ") if label else ""
        self.length         = length
        self.color_width    = None
        self.progress       = 0
        self.last           = 0

        # Insert spaces for missing length of label
        if self.label and len(self.label) < min_width:
            self.label += " " * (min_width - len(self.label))

    def __color_width(self):
        """Retrieves the terminals color width

        Returns:
            int: number of colors of the terminal

        """

        # Check if color_width is set
        if not self.color_width:
            curses.setupterm()
            self.color_width = curses.tigetnum("colors")

        return self.color_width

    def __bar_characters(self):
        """Retrieve bar characters depending on color mode

        Returns characters based on the assumption that 256 color terminals
        allows unicode output, and others don't.

        Returns:
            list: list of characters

        """

        return ["■", "□"] if int(self.__color_width()) == 256 else ["#", " "]

    def __print(self):
        """Formats and prints the progress bar with current properties

        Returns:
            int: length of printed output

        """

        #rows, columns = os.popen("stty size", "r").read().split()
        columns = 80
        bar_char = self.__bar_characters()
        percentage = "%.0f%%" % self.progress
        percentage = " " * (5 - len(percentage)) + percentage
        length = (self.length or int(columns) - 7)\
            - len(self.label)\
            - len(percentage)
        progress_bar = "["\
            + int(length / 100 * self.progress // 1) * bar_char[0]\
            + int(length - length / 100 * self.progress // 1) * bar_char[1]\
            + "]"
        progress_bar = "%s%s%s" % (self.label, progress_bar, percentage)

        # Rewind cursor to override last output
        UI.rewind(self.last)

        return UI.print(progress_bar, end="", symbol=Symbol.STATUS)

    def update(self, progress):
        """Updates progress and prints the progress bar

        Args:
            progress (int): progress of 0 to 100

        """

        self.progress   = progress
        self.last       = self.__print()    # Remember the length of the output

    def complete(self):
        """Completes the progress by setting it to 100, and prints a new line

        """

        self.update(100)
        UI.print()


class Scrambler(object):
    """Bit scrambler for higher level of obfuscation

    Attributes:
        data (list): list of bytes
        flag (byte): 8 flags indicating which algorithms to use
        reverse (bool): indicator of working order

    """

    def __init__(self, data, flag, reverse=False):
        """Initialize the scrambler

        Args:
            data (list): list of bytes
            flag (byte): byte with a value from 1 to 255 (at least one on)
            reverse (bool): indicator, default: False

        """

        self.data       = [x for x in data]
        self.flag       = flag
        self.reverse    = reverse

    def switch_all(self):
        """Switch all bits by XORing with all 1s

        """

        for i in range(len(self.data)):
            self.data[i] ^= 0xff

    def switch_even(self):
        """Switch even bits by XORing every second bit with 1

        """

        for i in range(len(self.data)):
            for j in range(4):
                self.data[i] ^= 1 << (j * 2)

    def switch_nth(self, number):
        """Switch every nth bit by XORing with them 1

        """

        for i in range(len(self.data)):
            for j in range(8):
                if (i * 8 + j) % number == 0:
                    self.data[i] ^= 1 << j

    def switch_sibling(self):
        """XOR all bytes with the value of it's previous sibling

        Note:
            The first byte will get XORed with the value of the flag

        """

        sibling = self.flag
        for i in range(len(self.data)):
            if i > 0:
                sibling = (
                    sibling ^ self.data[i - 1] if self.reverse
                    else self.data[i - 1]
                )

            self.data[i] ^= sibling

    def switch_flag(self):
        """XOR all bytes with the value of the flag

        """

        for i in range(len(self.data)):
            self.data[i] ^= self.flag

    def switch_rolling(self):
        """XOR all bytes with a rolling value of 0 through 255, again and again

        """

        for i in range(len(self.data)):
            self.data[i] ^= (i % 256)

    def scramble(self):
        """The main method performing the algorithms based in the flag

        Returns:
            list: the scrambled byte list

        """

        progress_data = ProgressBar(label=(
            "Unscrambling data" if self.reverse
            else "Scrambling data"
        ))
        methods = [
            self.switch_all,
            self.switch_even,
            lambda: self.switch_nth(3),
            lambda: self.switch_nth(5),
            lambda: self.switch_nth(7),
            self.switch_sibling,
            self.switch_flag,
            self.switch_rolling,
        ]

        for idx, i in enumerate(
            reversed(range(len(methods))) if self.reverse
            else range(len(methods))
        ):
            if (self.flag >> i) & 1:
                methods[i]()
            progress_data.update(idx * 100 // 8)
        progress_data.complete()

        return self.data


class Stega(object):
    """Steganographical class responsible for carrying out the main work

    Attributes:
        password (bytes): password used for encryption and seeding
        key (bytes): key generated from the password
        seed (bytes): seed generated from the password
        pixels (list): list of all the pixels being managed

    """

    def __init__(self, password):
        """Initialize Stega

        Args:
            password (bytes): the password being used for various things

        """

        self.password   = password
        self.key        = self.__get_key()
        self.seed       = self.__get_seed()
        self.pixels     = []

    def __get_key(self):
        """Calculates a 256 bit key by hashing the password

        Note:
            Used for AES encryption. Entropy relies on the password being
            secure enough.
        """

        return hashlib.sha256(self.password).digest()

    def __get_seed(self):
        """Calculates a 32 bit seed from a 128 hash of the key

        Note:
            The lowered level of entropy in the seed is no problem as this
            is applied together with the 256 bit AES encryption
        """

        return Utility.bits_to_int(
            Utility.get_bits(
                hashlib.md5(self.key).digest()
            )
        )

    def __get_pixel(self, pixel_id, color_id):
        """Retrieve the pixel and color data from pixels by given IDs

        Args:
            pixel_id (int): the id of the pixel
            color_id (int): the id of the color of the pixel

        Returns:
            obj: pixel data
            byte: color value

        """

        # Get pixel data
        pixel           = list(self.pixels[pixel_id])
        color           = pixel[color_id]

        # Return pixel data
        return pixel, color

    def __set_pixel(self, pixel_id, color_id, bit):
        """Sets the least significant bit of pixel and color by given IDs

        Args:
            pixel_id (int): the id of the pixel
            color_id (int): the id of the color of the pixel
            bit (bit): value to apply to the least significant bit

        """

        # Process pixel
        pixel, color    = self.__get_pixel(pixel_id, color_id)
        pixel[color_id] = Utility.set_bit(color, bit)

        # Set pixel
        self.pixels[pixel_id] = tuple(pixel)

    def __inject(self, data):
        """Injects data into the least significant bits of the pixel's color's

        Args:
            data (list): list of bytes to be injected

        """

        length          = [x for x in Utility.int_to_bits(len(data))]
        data            = [x for x in Utility.get_bits(data)]
        progress        = None
        progress_data   = ProgressBar(label="Injecting data")
        progress_noise  = ProgressBar(label="Injecting noise")

        # Inject length of data stream
        for i, bit in enumerate(length):
            self.__set_pixel(
                i // 3,
                i % 3,
                bit
            )

        random.seed(self.seed)
        sample = random.sample(
            range(12, len(self.pixels)),
            len(self.pixels) - 12
        )

        # Inject data stream
        for i, bit in enumerate(data):
            self.__set_pixel(
                sample[i // 3],
                i % 3,
                bit
            )

            # Update progress
            current = (i * 100 // len(data))
            if current != progress:
                progress    = current
                progress_data.update(progress)
        progress_data.complete()

        # Inject random noise
        for i in range(len(data), len(sample) * 3):
            self.__set_pixel(
                sample[i // 3],
                i % 3,
                random.getrandbits(1)
            )

            # Update progress
            current = ((i - len(data)) * 100 // (len(sample) * 3 - len(data)))
            if current != progress:
                progress    = current
                progress_noise.update(progress)
        progress_noise.complete()

    def __extract(self):
        """Extracts data from the pixel's color's least significant bits

        Returns:
            bytes: the bytes extracted

        """

        length          = []
        data            = []
        progress        = None
        progress_data   = ProgressBar(label="Extracting data")

        # Extracting length of data stream
        for i in range(32):
            pixel_color = self.__get_pixel(
                i // 3,
                i % 3
            )

            length.append(Utility.get_bit(pixel_color[1]))

        length = Utility.bits_to_int(length) * 8

        random.seed(self.seed)
        sample = random.sample(
            range(12, len(self.pixels)),
            -(-(length) // 3)
        )

        # Extracting data stream
        for i in range(length):
            pixel_color = self.__get_pixel(
                sample[i // 3],
                i % 3
            )

            data.append(Utility.get_bit(pixel_color[1]))

            current = (i * 100 // length)
            if current != progress:
                progress    = current
                progress_data.update(progress)
        progress_data.complete()

        return b"".join([bytes([x]) for x in Utility.get_bytes(data)])

    def __hide(self, image_filename, data, image_output_filename=None):
        """Hides the data steganographically inside a given image

        Note:
            If no output filename is specified, output will be written
            to STDOUT.

        Args:
            image_filename (str): the given image filename
            data (bytes): the data to be hidden
            image_output_filename: output filename, default: None

        """

        image = Image.open(image_filename)
        if image.mode in "RGBA":
            image = image.convert("RGBA")

            UI.print("Loading pixels...", symbol=Symbol.STATUS)
            self.pixels = [x for x in image.getdata()]

            if len(self.pixels) * 3 > len(data) * 8:
                self.__inject(data)

                UI.print("Saving data...", symbol=Symbol.STATUS)
                image.putdata(self.pixels)
                if image_output_filename:
                    image.save(image_output_filename, format="PNG")
                else:
                    with BytesIO() as output:
                        image.save(output, format="PNG")
                        with os.fdopen(sys.stdout.fileno(), "wb") as stream:
                            stream.write(output.getvalue())
                            stream.flush()

                UI.print(
                    "Successfully injected to %s"
                    % (image_output_filename or "STDOUT"),
                    symbol=Symbol.SUCCESS
                )
            else:
                UI.print("Data won't fit into the image", symbol=Symbol.ERROR)
        else:
            UI.print("Injection failed", symbol=Symbol.ERROR)

    def __retrieve(self, image_data):
        """Retrieves data from image data, assuming something is there

        Args:
            image_data (bytes): image data stream in byte format

        Returns:
            bytes: the data successfully extracted or an empty result

        """

        image = Image.open(BytesIO(image_data))
        if image.mode in "RGBA":
            image = image.convert("RGBA")

            UI.print("Loading pixels...", symbol=Symbol.STATUS)
            self.pixels = [x for x in image.getdata()]
            return self.__extract()
        return b""


    def encrypt(self, image_filename, data, image_output_filename=None):
        """The main function responsible for initializing the encryption

        Args:
            image_filename (str): the given image filename
            data (bytes): the data to be encrypted
            image_output_filename (str): alternative output, default: None

        """

        random.seed(self.seed)
        data = Scrambler(data, random.randint(1, 255)).scramble()

        UI.print("Encrypting data...", symbol=Symbol.STATUS)
        vector  = Random.new().read(AES.block_size)
        cipher  = AES.new(self.key, AES.MODE_CBC, vector)
        data    = data + [x for x in (
            (AES.block_size - len(data) % AES.block_size)
            * chr(AES.block_size - len(data) % AES.block_size)
        ).encode()]
        data    = vector + cipher.encrypt(b"".join([bytes([x]) for x in data]))

        self.__hide(image_filename, data, image_output_filename)

    def decrypt(self, image_data):
        """The main function responsible for initializing the decryption

        Args:
            image_data (bytes): byte stream of image data

        Returns:
            bytes: decrypted data

        """

        data    = self.__retrieve(image_data)
        vector  = data[:AES.block_size]
        data    = data[AES.block_size:]

        UI.print("Decrypting data...", symbol=Symbol.STATUS)
        cipher  = AES.new(self.key, AES.MODE_CBC, vector)
        data    = cipher.decrypt(data)
        data    = data[:-ord(data[len(data)-1:])]

        random.seed(self.seed)
        data = Scrambler(data, random.randint(1, 255), reverse=True).scramble()

        return b"".join([bytes([x]) for x in data])


class Main(object):
    """Wrapper for the main parts, called if not loaded as a module

    Initializes the CLI UI

    """

    @staticmethod
    def run():
        """The run method responsible for starting things up

        """

        parser = argparse.ArgumentParser(
            prog="stegame",
            description="""
            Encrypts or decrypts STDIN to STDOUT using steganography.
            """,
            add_help=False
        )

        root_group = parser.add_mutually_exclusive_group()

        root_group.add_argument(
            "IMAGE",
            nargs="?",
            action="store",
            default=None,
            help="image used for steganographical encryption"
        )
        root_group.add_argument(
            "-h", "--help",
            dest="help",
            action="store_true",
            help="show this help message and exit"
        )
        root_group.add_argument(
            "-V", "--version",
            action="version",
            version="%(prog)s 1.0"
        )
        root_group.add_argument(
            "-L", "--license",
            dest="license",
            action="store_true",
            help="show software license"
        )
        root_group.add_argument(
            "-d", "--decrypt",
            dest="decrypt",
            action="store_true",
            help="indicate decryption, used instead of IMAGE",
        )
        parser.add_argument(
            "-o", "--output",
            dest="output",
            action="store",
            type=str,
            help="redirect output to path instead of STDOUT",
            metavar="PATH"
        )

        args = parser.parse_args()
        if args.help:
            parser.print_help(sys.stderr)
            exit(0)

        if args.license:
            Main.print_license(sys.stderr)
            exit(0)

        if not select.select([sys.stdin,], [], [], .0)[0]:
            parser.error("STDIN is empty, nothing to process")
        else:
            UI.print_header()

            if args.decrypt:
                data        = sys.stdin.buffer.read()
                password    = getpass.getpass("Password: ").encode()
                stega       = Stega(password)

                UI.print()
                UI.print_heading("Performing data decryption...")

                data = stega.decrypt(data)

                if args.output:
                    with open(args.output, "wb") as output:
                        output.write(data)
                else:
                    with os.fdopen(sys.stdout.fileno(), "wb") as stream:
                        stream.write(data)
                        stream.flush()
                UI.print(
                    (
                        "Data successfully written to %s"
                        % (args.output or "STDOUT")
                    ), symbol=Symbol.SUCCESS
                )
            elif args.IMAGE:
                data        = sys.stdin.buffer.read()
                password    = None

                while not password:
                    password = getpass.getpass("Password: ")
                    if not password == getpass.getpass("Password RETYPE: "):
                        password = None
                        continue
                    password = password.encode()

                UI.print()
                UI.print_heading("Performing data encryption...")

                stega = Stega(password)
                stega.encrypt(args.IMAGE, data, args.output)
            else:
                parser.print_usage(sys.stderr)
                exit(2)

    @staticmethod
    def print_license(output=sys.stderr):
        """Method for printing the GPL license notice

        Args:
            output (obj:ioWrapper): output, default: STDERR

        """

        license_notice = "\
        \nStegaMe.py - Steganographical tool with encryption using passphrase\
        \nCopyright (C) 2018 z0noxz, <z0noxz@mail.com>\
        \n\
        \nThis program is free software: you can redistribute it and/or modify\
        \nit under the terms of the GNU General Public License as published by\
        \nthe Free Software Foundation, either version 3 of the License, or\
        \n(at your option) any later version.\
        \n\
        \nThis program is distributed in the hope that it will be useful,\
        \nbut WITHOUT ANY WARRANTY; without even the implied warranty of\
        \nMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\
        \nGNU General Public License for more details.\
        \n\
        \nYou should have received a copy of the GNU General Public License\
        \nalong with this program. If not, see <http://www.gnu.org/licenses/>.\
        \n\n"

        output.write(license_notice)
        output.flush()


# Check if the program is being called directly
if __name__ == "main" or True:
    Main.run()
