# NSE4 Libraries
# Copyright (C) 2023 - 2025 Alessandro Salerno

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


import os


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding

from mcom.protocol import MComProtocol

import unet.protocol as uprot


class UNetAESKey:
    def __init__(self, key: bytes, iv: bytes):
        self._key = key
        self._iv = iv

    def encrypt(self, message: bytes) -> bytes:
        padder = aes_padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(self._iv))
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, message: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(self._iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(message) + decryptor.finalize()
        unpadder = aes_padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_padded) + unpadder.finalize()

    @property
    def key(self):
        return self._key

    @property
    def iv(self):
        return self._iv


class UNetRSAMComProtocol(MComProtocol):
    def __init__(self,
                 base_prot: MComProtocol,
                 my_rsa_key: rsa.RSAPrivateKey,
                 other_rsa_key: rsa.RSAPublicKey) -> None:
        self._my_rsa_key = my_rsa_key
        self._other_rsa_key = other_rsa_key
        super().__init__(base_prot.socket)

    def send_bytes(self, message: bytes) -> None:
        cipher = self._other_rsa_key.encrypt(bytes(message), rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        return super().send_bytes(cipher)

    def recv_bytes(self) -> bytes:
        cipher = super().recv_bytes()
        return self._my_rsa_key.decrypt(
            cipher,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
        ))


class UNetAESMComProtocol(MComProtocol):
    def __init__(self, base_prot: MComProtocol, aes_key: UNetAESKey):
        self._aes_key = aes_key

    def send_bytes(self, message: bytes) -> None:
        return super().send_bytes(self._aes_key.encrypt(message))

    def recv_bytes(self) -> bytes:
        return self._aes_key.decrypt(super().recv_bytes())


def new_random_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=uprot.UNET_RSA_KEY_SIZE
    )


def reconstructrsa_public_key(exponent: int, modulus: int) -> rsa.RSAPublicKey:
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


def new_random_aes_keY():
    key = os.urandom(uprot.UNET_AES_KEY_SIZE)
    iv = os.urandom(uprot.UNET_AES_IV_SIZE)
    return UNetAESKey(key, iv)
