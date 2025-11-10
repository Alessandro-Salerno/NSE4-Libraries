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

from mcom.connection_handler import MComConnectionHandler
from mcom.client import MComClient

from unet.command_orchestrator import UNetCommandOrchestrator
from unet.command_handler import UNetCommandHandler
import unet.protocol as uprot
import unet.encryption as uenc


class UNetClientEncryptException(Exception):
    def __init__(self) -> None:
        super().__init__("Failed to secure connection with remote server")

class UNetClientConnectionMode:
    def __init__(self,
                 mode: str,
                 name: str,
                 email: str,
                 password: str,
                 discord_userid: str,
                 agent: str) -> None:
        self._mode = mode
        self._name = name
        self._email = email
        self._password = password
        self._discord_userid = discord_userid
        self._agent = agent
    
    @property
    def mode(self):
        return self._mode
    
    @property
    def name(self):
        return self._name
    
    @property
    def email(self):
        return self._email

    @property
    def password(self):
        return self._password

    @property
    def discord_userid(self):
        return self._discord_userid

    @property
    def agent(self):
        return self._agent


class UNetClient(MComClient):
    def __init__(self,
                 conn_mode: UNetClientConnectionMode,
                 local_command_handler: UNetCommandHandler,
                 server_address: str,
                 server_port=19055,
                 connection_handler_class=MComConnectionHandler) -> None:
        
        self._conn_mode = conn_mode
        self._local_command_handler = local_command_handler
        self._local_command_handler.set_top(self)
        super().__init__(server_address, server_port, connection_handler_class)
        self._local_command_handler.set_parent(self._connection)
        self._connection.join()

    def on_connect(self):
        my_rsa_key = uenc.new_random_rsa_key()
        self.protocol.send(uprot.unet_make_encrypt_message(my_rsa_key.public_key()))

        encrypt_msg = self.protocol.recv()
        encrypt_json = json.loads(encrypt_msg)
        
        if encrypt_json['type'] != uprot.UNetMessageType.ENCRYPT:
            self.protocol.socket.close()
            raise UNetClientEncryptException()

        e, n = uprot.unet_read_encrypt_message(encrypt_json)
        server_rsa_key = uenc.reconstructrsa_public_key(e, n)
        self.protocol = uenc.UNetRSAMComProtocol(self.protocol, my_rsa_key, server_rsa_key)
        
        raw_aes_key = self.protocol.recv_bytes()
        raw_aes_iv = self.protocol.recv_bytes()

        if len(raw_aes_key) != uprot.UNET_AES_KEY_SIZE / 8 \
                or len(raw_aes_iv) != uprot.UNET_AES_IV_SIZE / 8:
            self.protocol.socket.close()
            raise UNetClientEncryptException()

        aes_key = uenc.UNetAESKey(raw_aes_key, raw_aes_iv)
        self.protocol = uenc.UNetAESMComProtocol(self.protocol, aes_key)
        
    def post_connect(self):
        self._command_orchestrator = UNetCommandOrchestrator(self._local_command_handler, self.protocol)
        self.protocol.send(uprot.unet_make_auth_message(
            mode=self.conn_mode.mode,
            name=self.conn_mode.name,
            email=self.conn_mode.email,
            password=self.conn_mode.password,
            discord_userid=self.conn_mode.discord_userid,
            agent=self.conn_mode.agent
        ))

    @property
    def command_orchestrator(self):
        if not hasattr(self, '_command_orchestrator'):
            return None
        
        return self._command_orchestrator

    @property
    def conn_mode(self):
        return self._conn_mode
