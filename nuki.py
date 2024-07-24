"""
Reference:
https://developer.nuki.io/page/nuki-smart-lock-api-2/2

Author:
Kan Xu
kan@kanxu.de
"""

from dataclasses import dataclass
from typing import ClassVar
import hmac, hashlib
from nacl.utils import random
import json, asyncio, logging
from nacl.public import PrivateKey, PublicKey
from nacl.bindings.crypto_box import crypto_box_beforenm
from nacl.secret import SecretBox
from datetime import datetime
from argparse import ArgumentParser
from bleak import BleakScanner, BleakClient


def crc16_xmodem(data:bytearray)->bytes:
    """
    Algorithm: CRC-CCITT(-FALSE)
    Polynomial representation: normal (0x1021)
    Initial remainder: 0xFFFF
    """
    CRC16_XMODEM_TABLE = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
        0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
        0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
        0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
        0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
        0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
        0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
        0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
        0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
        0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
        0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
        0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
        0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
        0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
        0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
        ]

    crc = 0xffff
    for b in data:
        crc = ((crc << 8) & 0xff00) ^ CRC16_XMODEM_TABLE[((crc >> 8) & 0xff) ^ b]
    return (crc & 0xffff).to_bytes(2, 'little')


def verify_crc(data:bytes)->None:
    crc = crc16_xmodem(data[0:-2])
    if crc != data[-2:]:
        raise CheckSumError(data.hex())

class ClientAuthSecret:
    def __init__(self, config_file:str):
        
        self.private_key = bytes()
        self.public_key = bytes()
        self.public_key_nuki = bytes()
        self.auth_id = 0
        self.uuid = b'\0' * 32

        try:
            with open(config_file) as r:
                jdat = json.load(r)
            
            self.private_key = bytes.fromhex(jdat['private_key'])
            self.public_key = bytes.fromhex(jdat['public_key'])
            self.public_key_nuki = bytes.fromhex(jdat['public_key_nuki'])
            self.auth_id = jdat['auth_id']
            self.uuid = bytes.fromhex(jdat['uuid'])
        except FileNotFoundError:
            logging.error('FileNotFound. New key pair will be generated.')
            self.gen_key_pair()
    
    def dump(self, config_file:str):
        dat = dict()
        dat['private_key'] = self.private_key.hex()
        dat['public_key'] = self.public_key.hex()
        dat['public_key_nuki'] = self.public_key_nuki.hex()
        dat['auth_id'] = self.auth_id
        dat['uuid'] = self.uuid.hex()
        with open(config_file, 'w') as w:
            json.dump(dat, w, indent=4)
    
    def __str__(self):
        lines = list()
        lines.append(f'Public key:      {self.public_key.hex()}')
        lines.append(f'Private key:     {self.private_key.hex()}')
        lines.append(f'Public key Nuki: {self.public_key_nuki.hex()}')
        lines.append(f'Auth-ID:         {self.auth_id}')
        lines.append(f'UUID:            {self.uuid.hex()}')
        return '\n'.join(lines)
    
    def gen_key_pair(self):
        kp = PrivateKey.generate()
        self.private_key = bytes(kp)
        self.public_key = bytes(kp.public_key)
    
    @property
    def shared_key(self):
        if not hasattr(self, '_shared_key'):
            self._shared_key = crypto_box_beforenm(self.public_key_nuki, self.private_key)
        
        return self._shared_key

@dataclass
class MessageContent:
    cid:ClassVar[int] = 0x0000

    def gen_message(self, playload:bytes)->bytes:
        data =  self.cid.to_bytes(2, 'little') + playload
        crc = crc16_xmodem(data)
        return data + crc

    def body(self):
        raise CommandUsageError(f'The command 0x{self.cid:04X} cannot be used as an outcomming message.')

@dataclass
class MsgRequestData(MessageContent):
    cid:ClassVar[int] = 0x0001
    request_cid: int
    
    def body(self)->bytes:
        return self.gen_message(self.request_cid.to_bytes(2, 'little'))
    
    def body_encrypted(self, auth_id:int, shared_key:bytes)->bytes:
        pdata = auth_id.to_bytes(4, 'little') + self.cid.to_bytes(2, 'little') + self.request_cid.to_bytes(2, 'little')
        pdata = pdata + crc16_xmodem(pdata)
        nonce = random(24)
        box = SecretBox(shared_key)
        pdata_cipher = bytes(box.encrypt(pdata, nonce))
        pdata_cipher = pdata_cipher[len(nonce):]
        return nonce + auth_id.to_bytes(4, 'little') + len(pdata_cipher).to_bytes(2, 'little') + pdata_cipher

@dataclass
class MsgPublicKey(MessageContent):
    cid:ClassVar[int] = 0x0003
    public_key: bytes
    def body(self)->bytes:
        return self.gen_message(self.public_key)

@dataclass
class MsgChallange(MessageContent):
    cid:ClassVar[int] = 0x0004
    nonce: bytes

@dataclass
class MsgAuthAuthenticator(MessageContent):
    cid:ClassVar[int] = 0x0005
    public_key: bytes
    public_key_server: bytes
    nonce: bytes
    def body(self, **kwargs)->bytes:
        value_R = bytes(self.public_key) + bytes(self.public_key_server) + self.nonce
        auth = hmac.new(kwargs['shared_key'], value_R, digestmod=hashlib.sha256).digest()
        return self.gen_message(auth)

@dataclass
class MsgAuthData(MessageContent):
    cid:ClassVar[int] = 0x0006
    id_type: int
    app_id: int
    name: str
    nonce: bytes

    def body(self, **kwargs)->bytes:
        id_type = self.id_type.to_bytes(1, 'little')
        app_id = self.app_id.to_bytes(4, 'little')
        name = self.name.encode('utf-8').ljust(32, b'\0')
        nonce_app = random(32)
        value_R = id_type + app_id + name + nonce_app + self.nonce
        auth = hmac.new(kwargs['shared_key'], value_R, digestmod=hashlib.sha256).digest()
        return self.gen_message(auth + id_type + app_id + name + nonce_app)


@dataclass
class MsgAuthId(MessageContent):
    cid:ClassVar[int] = 0x0007
    auth_id: int
    uuid: bytes
    nonce: bytes

@dataclass
class MsgAuthIdConfirm(MessageContent):
    cid:ClassVar[int] = 0x001E
    auth_id: int
    nonce: bytes

    def body(self, **kwargs)->bytes:
        value_R = self.auth_id.to_bytes(4, 'little') + self.nonce
        auth = hmac.new(kwargs['shared_key'], value_R, digestmod=hashlib.sha256).digest()
        return self.gen_message(auth + self.auth_id.to_bytes(4, 'little'))

@dataclass
class MsgStatus(MessageContent):
    cid:ClassVar[int] = 0x000E
    status: int
    def __str__(self):
        match self.status:
            case 0:
                return 'Status 0x00: Complete.'
            case 1:
                return 'Status 0x01: Accepted.'
            case _:
                return f'Status 0x{self.status:02X}.'


@dataclass
class MsgErrorReport(MessageContent):
    cid:ClassVar[int] = 0x0012
    error_code:int
    command_identifier:int

@dataclass
class MsgLockAction(MessageContent):
    cid:ClassVar[int] = 0x000D
    lock_action:int
    app_id:int
    flags:int
    name_suffix:str
    nonce:bytes

    def body_encrypted(self, auth_id:int, shared_key:bytes)->bytes:
        pdata = auth_id.to_bytes(4, 'little') + self.cid.to_bytes(2, 'little') \
                + self.lock_action.to_bytes(1, 'little') + self.app_id.to_bytes(4, 'little') + self.flags.to_bytes(1, 'little') \
                + self.name_suffix[0:20].encode('utf-8').ljust(20, b'\0') + self.nonce
        pdata = pdata + crc16_xmodem(pdata)
        box = SecretBox(shared_key)
        nonce_app = random(24)
        pdata_cipher = bytes(box.encrypt(pdata, nonce_app))
        pdata_cipher = pdata_cipher[len(nonce_app):]
        return nonce_app + auth_id.to_bytes(4, 'little') + len(pdata_cipher).to_bytes(2, 'little') + pdata_cipher        


@dataclass
class MsgKeyturnerStates(MessageContent):
    NUKI_STATE:ClassVar[dict] = { 0x0: 'Uninitialized', 0x1: 'Pairing Mode', 0x2: 'Door Mode', 0x4: 'Maintenance Mode'}
    LOCK_STATE:ClassVar[dict] = { 0x0: 'uncalibrated', 0x1: 'locked', 0x2: 'unlocking', 0x3: 'unlocked', 0x4: 'locking',
                                  0x5: 'unlatched', 0x6: 'unlocked (lock&go)', 0x7: 'unlatching', 0xfc: 'calibration',
                                  0xfd: 'boot run', 0xfe: 'motor blocked'}

    cid:ClassVar[int] = 0x000C

    nuki_state:int
    lock_state:int
    trigger:int
    current_time:datetime
    timezone_offset:int
    critical_battery_state:bool
    charging:bool
    battery_level:int
    config_update_count:int
    lock_n_go_timer:int
    last_lock_action:int
    last_lock_action_trigger:int
    last_lock_action_completion_status:int
    door_sensor_state:int
    night_mode:int
    accessory_battery_state:int

    def __str__(self):
        s = list()
        s.append('Nuki Smart Lock status:')
        s.append(f'Nuki state:    {self.NUKI_STATE.get(self.nuki_state, "undefined")}')
        s.append(f'Lock state:    {self.LOCK_STATE.get(self.lock_state, "undefined")}')
        s.append(f'Date/Time:     {self.current_time.isoformat()}')
        s.append(f'Battery:       {self.battery_level}%')
        s.append(f'Battery state: {"Critical" if self.critical_battery_state else "Normal"}')
        return '\n'.join(s)


class CommandNotSupportError(BaseException):
    pass

class CheckSumError(BaseException):
    pass

class CommandUsageError(BaseException):
    pass

class DeviceNotFound(BaseException):
    pass

   
def message_from_bytes(msg:bytes, crc_check=True, **kwargs):
    msg = bytes(msg)
    if crc_check:
        verify_crc(msg)
    cid = int.from_bytes(msg[0:2], 'little')
    payload = msg[2:-2]
    match cid:
        case 0x0003:
            c = MsgPublicKey(public_key=payload[0:32])
        case 0x0004:
            if kwargs and 'nonce' in kwargs:
                c = MsgChallange(nonce=kwargs['nonce'])
            else:
                c = MsgChallange(nonce=payload[0:32])
        case 0x0007:
            c = MsgAuthId(auth_id=int.from_bytes(payload[32:36], 'little'), uuid=payload[36:52], nonce=payload[52:84])
        case 0x000E:
            c = MsgStatus(status=payload[0])
        case 0x0012:
            c = MsgErrorReport(error_code=int.from_bytes(payload[0:1], 'little'), command_identifier=int.from_bytes(payload[1:3], 'little'))
        case 0x000C:
            c = MsgKeyturnerStates(
                nuki_state=int(payload[0]),
                lock_state=int(payload[1]),
                trigger=int(payload[2]),
                current_time=datetime(
                        year=int.from_bytes(payload[3:5], 'little'),
                        month=int(payload[5]),
                        day=int(payload[6]),
                        hour=int(payload[7]),
                        minute=int(payload[8]),
                        second=int(payload[9])),
                timezone_offset=int.from_bytes(payload[10:12], 'little', signed=True),
                critical_battery_state=bool(payload[12] & 0x1),
                charging=bool(payload[12] & 0x2),
                battery_level=int(payload[12]>>2)*2,
                config_update_count=int(payload[13]),
                lock_n_go_timer=int(payload[14]),
                last_lock_action=int(payload[15]),
                last_lock_action_trigger=int(payload[16]),
                last_lock_action_completion_status=int(payload[17]),
                door_sensor_state=int(payload[18]),
                night_mode=int.from_bytes(payload[19:21], 'little'),
                accessory_battery_state=int(payload[21])
            )
    try:
        return c
    except UnboundLocalError:
        raise CommandNotSupportError(f'The command identifier 0x{cid:04X} is not supported.')


def message_from_cipher(msg:bytes, shared_key:bytes):
    msg = bytes(msg)
    nonce = msg[0:24]
    auth_id = int.from_bytes(msg[24:28], 'little')
    length = int.from_bytes(msg[28:30], 'little')
    cipher = msg[30:]
    assert(length == len(cipher))
    box = SecretBox(shared_key)
    plain = box.decrypt(cipher, nonce)
    verify_crc(plain)
    assert(auth_id == int.from_bytes(plain[0:4], 'little'))
    return message_from_bytes(plain[4:], False)


class DeviceFinder:
    UUID_OPERATION = 'a92ee200-5501-11e4-916c-0800200c9a66'
    UUID_AUTH = 'a92ee100-5501-11e4-916c-0800200c9a66'

    def __init__(self, mac:str):
        self.address = mac
        self.stop_event = asyncio.Event()
        self.device = None
        self.service_uuid = ''
    
   
    def callback(self, dev, adv_data):
        if dev.address == self.address:
            if len(self.service_uuid) == 0 or (self.service_uuid in adv_data.service_data):
                self.device = dev
                self.stop_event.set()
    
    async def search(self):
        logging.info('Discovering Nuki device via BLE...')
        self.service_uuid = ''
        return await self._search()
    
    async def auth(self):
        logging.info('Discovering pairable Nuki device via BLE...')
        self.service_uuid = self.UUID_AUTH
        return await self._search()

    async def _search(self):
        self.device = None
        self.stop_event.clear()
        async with BleakScanner(detection_callback=self.callback, scanning_mode='active') as scanner:
            try:
                await asyncio.wait_for(self.stop_event.wait(), 30)
            except asyncio.exceptions.TimeoutError:
                raise DeviceNotFound()
        
        return self.device


UUID_AUTH_GDIO = 'a92ee101-5501-11e4-916c-0800200c9a66'
UUID_USDIO = 'a92ee202-5501-11e4-916c-0800200c9a66'
UUID_GDIO = 'a92ee201-5501-11e4-916c-0800200c9a66'

class NukiOperation:

    def __init__(self, dev, secrets_file:str):
        self.device = dev
        self.client = BleakClient(dev, disconnected_callback=self.handler_disconnected, timeout=30.0)
        self.current_response = bytearray()
        self.staged_message = bytearray()
        self.event = asyncio.Event()
        self.secrets_file = secrets_file
        self.secrets = ClientAuthSecret(self.secrets_file)
    
    async def __aenter__(self):
        await self.client.connect()
        logging.info(f'Connection to {self.device.name} established.')
        return self
    
    async def __aexit__(self, *_):
        await self.client.disconnect()
    
    def handler_disconnected(self, dev):
        logging.info(f'Connection to {self.device.name} terminated.')
        self.event.set()
    
    async def status(self):
        self.current_response = bytearray()
        await self.client.start_notify(UUID_USDIO, self.cipher_received)
        await self.client.start_notify(UUID_GDIO, self.message_received)

        msg = MsgRequestData(0x000C)
        resp:MsgKeyturnerStates = await self.send_message(msg.body_encrypted(self.secrets.auth_id, self.secrets.shared_key), UUID_USDIO)
        return resp

    async def lock(self, annotation='Unknown'):
        await self.lock_action(0x2, annotation)

    async def unlock(self, annotation='Unknown'):
        await self.lock_action(0x1, annotation)
    
    async def unlatch(self, annotation='Unknown'):
        await self.lock_action(0x3, annotation)

    async def lock_action(self, action:int, annotation='Unknown'):
        self.current_response = bytearray()
        await self.client.start_notify(UUID_USDIO, self.cipher_received)
        await self.client.start_notify(UUID_GDIO, self.message_received)

        msg1 = MsgRequestData(0x0004)
        resp1:MsgChallange = await self.send_message(msg1.body_encrypted(self.secrets.auth_id, self.secrets.shared_key), UUID_USDIO)

        msg2 = MsgLockAction(action, 0, 0, annotation, resp1.nonce)
        resp:MsgStatus = await self.send_message(msg2.body_encrypted(self.secrets.auth_id, self.secrets.shared_key), UUID_USDIO)
        r_value = resp
        while True:
            logging.info(resp)
            if isinstance(resp, MsgStatus) and resp.status == 0:
                break
            resp = await self.send_message(None, None)
        
        return r_value
    
    async def authentificate(self, name:str):
        logging.info('Authentification process started.')
        self.current_response = bytearray()

        await self.client.start_notify(UUID_AUTH_GDIO, self.message_received)

        # STEP 1:
        # CL writes Request Data command with Public Key command identifier to GDIO
        # SL responses with its public key via multiple indications on GDIO        
        msg_st1 = MsgRequestData(0x0003)
        resp_st1:MsgPublicKey = await self.send_message(msg_st1.body(), UUID_AUTH_GDIO)
        assert(resp_st1.cid == 0x0003)
        self.secrets.public_key_nuki = resp_st1.public_key
        logging.debug(f'Public key of Nuki received: {self.secrets.public_key_nuki.hex()}')

        # STEP 2:
        # CL writes Public Key command to GDIO
        # SL sends Challenge command via multiple indications on GDIO
        msg_st2 = MsgPublicKey(self.secrets.public_key)
        resp_st2:MsgChallange = await self.send_message(msg_st2.body(), UUID_AUTH_GDIO)
        assert(resp_st2.cid == 0x0004)
  
        # STEP 3: 
        # CL writes Authorization Authenticator command with authenticator a to GDIO
        # SL sends Challenge command via multiple indications on GDIO
        msg_st3 = MsgAuthAuthenticator(self.secrets.public_key, self.secrets.public_key_nuki, resp_st2.nonce)
        resp_st3:MsgChallange = await self.send_message(msg_st3.body(shared_key=self.secrets.shared_key), UUID_AUTH_GDIO)
        assert(resp_st3.cid == 0x0004)

        # STEP 4: 
        # CL writes Authorization Data command to GDIO
        # SL sends Authorization-ID command via multiple indications on GDIO
        # TODO: APP ID shall not be alwasy the same!!!
        msg_st4 = MsgAuthData(0, 0, name, resp_st3.nonce)
        resp_st4:MsgAuthId = await self.send_message(msg_st4.body(shared_key=self.secrets.shared_key), UUID_AUTH_GDIO)
        assert(resp_st4.cid == 0x0007)
        self.secrets.uuid = resp_st4.uuid
        self.secrets.auth_id = resp_st4.auth_id
        logging.debug(str(self.secrets))
        self.secrets.dump(self.secrets_file)
        
        # STEP 5:
        # CL writes Authorization-ID Confirmation command to GDIO
        # SL sends Status COMPLETE via multiple indications on GDIO
        msg_st5 = MsgAuthIdConfirm(self.secrets.auth_id, resp_st4.nonce)
        resp_st5:MsgStatus = await self.send_message(msg_st5.body(shared_key=self.secrets.shared_key), UUID_AUTH_GDIO)
        logging.info(resp_st5)

        await self.client.stop_notify(UUID_AUTH_GDIO)

    async def send_message(self, msg:bytes, char:str)->MessageContent:
        self.event.clear()
        if msg is not None:
            logging.debug(f'Sending message: {msg.hex()}')
            await self.client.write_gatt_char(char, msg)
        
        await asyncio.wait_for(self.event.wait(), 15)
        if not self.client.is_connected:
            raise ConnectionAbortedError()
        
        return self.staged_message
    
    def cipher_received(self, _, data:bytearray):
        logging.debug(f'Cipher data received: {data.hex()}')
        self.staged_message = message_from_cipher(data, self.secrets.shared_key)
        if isinstance(self.staged_message, MsgErrorReport):
            logging.error(self.staged_message)
        else:
            logging.debug(f'Encrypted message received: {self.staged_message}')
        self.event.set()
    
    def message_received(self, _, data:bytearray):
        logging.debug(f'Raw data received: {data.hex()}')
        self.current_response += data

        self.staged_message = message_from_bytes(self.current_response)
        self.current_response = bytearray()
        if isinstance(self.staged_message, MsgErrorReport):
            logging.error(self.staged_message)
        else:
            logging.debug(f'Message received: {self.staged_message}')
        self.event.set()

async def operation_status(args):
    dev = await DeviceFinder(args.address).search()
    async with NukiOperation(dev, args.secrets) as oper:
        status = await oper.status()
        print(status)


async def operation_unlock(args):
    dev = await DeviceFinder(args.address).search()
    async with NukiOperation(dev, args.secrets) as oper:
        await oper.unlock(args.annotation)

async def operation_lock(args):
    dev = await DeviceFinder(args.address).search()
    async with NukiOperation(dev, args.secrets) as oper:
        await oper.lock(args.annotation)

async def operation_unlatch(args):
    dev = await DeviceFinder(args.address).search()
    async with NukiOperation(dev, args.secrets) as oper:
        await oper.unlatch(args.annotation)

async def operation_search(args):
    dev = await DeviceFinder('54:D2:72:FD:60:15').auth()
    print(dev)

async def operation_auth(args):
    logging.info('Press the button on Nuki smart lock for 5 seconds to enter authentification mode.')
    dev = await DeviceFinder(args.address).auth()
    async with NukiOperation(dev, args.secrets) as oper:
        await oper.authentificate(args.name) 




async def perform_unlatch(address:str, secret_file:str, annotation:str):
    dev = await DeviceFinder(address).search()
    async with NukiOperation(dev, secret_file) as oper:
        await oper.unlatch(annotation)


if __name__ == '__main__':
    DEFAULT_NUKI = '54:D2:72:FD:60:15'

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s")

    operations = {
        'status': operation_status,
        'lock': operation_lock,
        'unlock': operation_unlock,
        'auth': operation_auth,
        'search': operation_search,
        'unlatch': operation_unlatch
    }

    parser = ArgumentParser(description='Nuki Smartlock operation.')
    parser.add_argument('--address', '-a', default=DEFAULT_NUKI, help='MAC address of the BLE device.')
    parser.add_argument('--secrets', '-s', default='secrets.json', help='A json file contains the keys and authentification ID.')
    parser.add_argument('--annotation', '-n', default='NA', help='Infomation text will logged in Nuki device.')
    parser.add_argument('operation', help='Action to take [auth, lock, status, unlatch, unlock].')
    args = parser.parse_args()

    asyncio.run(operations[args.operation](args))

