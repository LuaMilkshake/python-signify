# Copyright 2017 John "LuaMilkshake" Marion
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""signify - Python implementation of OpenBSD's signify

Currently for signature verification only. Note that implementing
the secret parts of signify in Python should also concern memory
handling (explicit_bzero etc).
"""

import base64

import ed25519


_COMMENTHDR = "untrusted comment: "
_COMMENTMAXLEN = 1024
_PKALG = b"Ed"
_SIGBYTES = 64
_PUBLICKEYBYTES = 32
_KEYNUMLEN = 8


def _read_signify_file(filepath: str) -> bytes:
    """Read a file in the signify format and return decoded bytes.

    As in the OpenBSD implementation, this also verifies some
    properties of the untrusted comment (length, 'untrusted comment: ').

    Takes:
        filepath: str - Path of the file to read

    Returns: bytes - Base64-decoded file contents.

    Raises:
        TODO
    """
    with open(filepath) as file:
        comment = file.readline()
        if comment[:len(_COMMENTHDR)] != _COMMENTHDR:
            raise Exception("invalid comment in {}, "
                            "must start with '{}'".format(filepath,
                                                          _COMMENTHDR))
        if len(comment) - len(_COMMENTHDR) > _COMMENTMAXLEN:
            raise Exception("comment too long in {}".format(filepath))

        filedata = base64.b64decode(file.readline())
        if filedata[:len(_PKALG)] != _PKALG:
            raise Exception("unsupported file {}".format(filepath))
        return filedata


def _sig_dict(sig_data: bytes) -> dict:
    """Marshal out a signature from the sig file format.

    Returns: dict - Signature
        - pkalg: Constant 'Ed'
        - keynum: Key number
        - sig: Signature bytes
    """
    # struct sig {
    # 	uint8_t pkalg[2];
    # 	uint8_t keynum[KEYNUMLEN];
    # 	uint8_t sig[SIGBYTES];
    # };

    keynum_offset = len(_PKALG)
    sig_offset = keynum_offset + _KEYNUMLEN

    sig = {}
    sig['pkalg'] = sig_data[:len(_PKALG)]
    sig['keynum'] = sig_data[keynum_offset:keynum_offset + _KEYNUMLEN]
    sig['sig'] = sig_data[sig_offset:sig_offset + _SIGBYTES]
    return sig


def _pubkey_dict(pubkey_data: bytes) -> dict:
    """Marshal out a public key from the key file format.

    Returns: dict - Public key
        - pkalg: Constant 'Ed'
        - keynum: Key number
        - pubkey: Public key bytes
    """
    # struct pubkey {
    # 	uint8_t pkalg[2];
    # 	uint8_t keynum[KEYNUMLEN];
    # 	uint8_t pubkey[PUBLICBYTES];
    # };

    keynum_offset = len(_PKALG)
    key_offset = keynum_offset + _KEYNUMLEN

    key = {}
    key['pkalg'] = pubkey_data[:len(_PKALG)]
    key['keynum'] = pubkey_data[keynum_offset:keynum_offset + _KEYNUMLEN]
    key['pubkey'] = pubkey_data[key_offset:key_offset + _PUBLICKEYBYTES]
    return key


def verify_files(message: str, signature: str, pubkey: str) -> bool:
    """Verify a message using signify.

    Equivalent to `signify -V ...`. Does not (yet) support embedded
    signatures.

    Takes:
        message: str - File path containing message plaintext to
                       verify against
        signature: str - File path containing base64-encoded message
                         signature (detached signature)
        pubkey: str - File path containing base64-encoded public key
                      to verify against

    Returns: bool - Validity of signature
    """
    sig_data = _read_signify_file(signature)
    pubkey_data = _read_signify_file(pubkey)

    sig = _sig_dict(sig_data)
    pub = _pubkey_dict(pubkey_data)

    if pub['keynum'] != sig['keynum']:
        raise Exception('verification failed: checked against wrong key')

    with open(message, 'rb') as message_file:
        message_data = message_file.read()

    key = ed25519.VerifyingKey(pub['pubkey'])
    try:
        key.verify(sig['sig'], message_data)
    except ed25519.BadSignatureError:
        return False

    return True
