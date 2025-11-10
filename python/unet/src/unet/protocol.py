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


import json
from cryptography.hazmat.primitives.asymmetric import rsa


UNET_PROTOCOL_VERSION = '1.1.0'
UNET_RSA_KEY_SIZE = 4096
UNET_AES_KEY_SIZE=256
UNET_AES_IV_SIZE=16


class UNetMessageType:
    ENCRYPT = 'ENCRYPT'
    AUTH = 'AUTH'
    STATUS = 'STATUS'
    VALUE = 'VALUE'
    TABLE = 'TABLE'
    CHART = 'CHART'
    MULTI = 'MULTI'


class UNetAuthMode:
    LOGIN = 'LOGIN'
    SIGNUP = 'SIGNUP'


class UNetStatusMode:
    OK = 'OK'
    ERR = 'ERR'


class UNetStatusCode:
    DONE = 'DONE'
    EXC = 'EXC'
    BAD = 'BAD'
    VER = 'VER'
    DENY = 'DENY'


def unet_make_message(**kwargs):
    return json.dumps(kwargs)


def unet_make_encrypt_message(rsa_public_key: rsa.RSAPublicKey):
    return unet_make_message(
        type=UNetMessageType.ENCRYPT,
        version=UNET_PROTOCOL_VERSION, # retro compatibility
        exponent=str(rsa_public_key.public_numbers().e),
        modulus=str(rsa_public_key.public_numbers().n)
    )


def unet_make_auth_message(mode: str, name: str, email: str, password: str, discord_userid: str, agent: str):
    return unet_make_message(
        type=UNetMessageType.AUTH,
        version=UNET_PROTOCOL_VERSION,
        mode=mode,
        name=name,
        email=email,
        password=password,
        discord_userid=discord_userid,
        agent=agent
    )


def unet_make_status_message(mode: str, code: str, message: str|dict):
    return unet_make_message(
        type=UNetMessageType.STATUS,
        mode=mode,
        code=code,
        message=message
    )


def unet_make_table_message(title: str, columns: list, rows: list):
    return unet_make_message(
        type=UNetMessageType.TABLE,
        title=title,
        columns=columns,
        rows=rows
    )


def unet_make_chart_message(*series, title: str, xformat: str, xlabel: str, ylabel: str):
    return unet_make_message(
        type=UNetMessageType.CHART,
        title=title,
        xformat=xformat,
        xlabel=xlabel,
        ylabel=ylabel,
        series=series
    )


def unet_make_chart_series(name: str, x: list, y: list):
    return {
        'name': name,
        'x': x,
        'y': y
    }


def unet_make_multi_message(*messages):
    return unet_make_message(
        type=UNetMessageType.MULTI,
        messages=messages
    )


def unet_make_value_message(name: str, value: any):
    return unet_make_message(
        type=UNetMessageType.VALUE,
        name=name,
        value=value
    )


def unet_read_encrypt_message(message: dict):
    return int(message['exponent']), int(message['modulus'])
