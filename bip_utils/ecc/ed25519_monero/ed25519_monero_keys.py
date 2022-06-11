# Copyright (c) 2021 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Module for ed25519-monero keys."""

# Imports
from typing import Any
from bip_utils.ecc.ed25519_monero.ed25519_monero_point import Ed25519MoneroPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.common.ikeys import IPoint, IPublicKey, IPrivateKey
from bip_utils.ecc.ed25519_monero.lib import ed25519_monero_lib
from bip_utils.utils.misc import DataBytes


class Ed25519MoneroKeysConst:
    """Class container for ed25519-monero keys constants."""

    # Compressed public key length in bytes
    PUB_KEY_COMPRESSED_BYTE_LEN: int = 32
    # Uncompressed public key length in bytes
    PUB_KEY_UNCOMPRESSED_BYTE_LEN: int = 32
    # Private key length in bytes
    PRIV_KEY_BYTE_LEN: int = 32


class Ed25519MoneroPublicKey(IPublicKey):
    """Ed25519-Monero public key class."""

    m_ver_key: bytes

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes) -> IPublicKey:
        """
        Construct class from key bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPublicKey: IPublicKey object

        Raises:
            ValueError: If key bytes are not valid
        """
        return cls(key_bytes)

    @classmethod
    def FromPoint(cls,
                  key_point: IPoint) -> IPublicKey:
        """
        Construct class from key point.

        Args:
            key_point (IPoint object): Key point

        Returns:
            IPublicKey: IPublicKey object

        Raises:
            ValueError: If key point is not valid
        """
        return cls(key_point.Raw().ToBytes())

    def __init__(self,
                 key_obj: Any) -> None:
        """
        Construct class from key object.

        Args:
            key_obj (class): Key object

        Raises:
            TypeError: If key object is not of the correct type
            ValueError: If key is not valid
        """
        if not isinstance(key_obj, bytes):
            raise TypeError("Invalid public key object type")
        if not ed25519_monero_lib.is_valid_pub_key(key_obj):
            raise ValueError("Invalid public key")

        self.m_ver_key = key_obj

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519_MONERO

    @staticmethod
    def CompressedLength() -> int:
        """
        Get the compressed key length.

        Returns:
           int: Compressed key length
        """
        return Ed25519MoneroKeysConst.PUB_KEY_COMPRESSED_BYTE_LEN

    @staticmethod
    def UncompressedLength() -> int:
        """
        Get the uncompressed key length.

        Returns:
           int: Uncompressed key length
        """
        return Ed25519MoneroKeysConst.PUB_KEY_UNCOMPRESSED_BYTE_LEN

    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_ver_key

    def RawCompressed(self) -> DataBytes:
        """
        Return raw compressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_ver_key)

    def RawUncompressed(self) -> DataBytes:
        """
        Return raw uncompressed public key.

        Returns:
            DataBytes object: DataBytes object
        """

        # Same as compressed
        return self.RawCompressed()

    def Point(self) -> IPoint:
        """
        Get public key point.

        Returns:
            IPoint object: IPoint object
        """
        return Ed25519MoneroPoint.FromBytes(self.m_ver_key)


class Ed25519MoneroPrivateKey(IPrivateKey):
    """Ed25519-Monero private key class."""

    m_sign_key: bytes

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes) -> IPrivateKey:
        """
        Construct class from key bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPrivateKey: IPrivateKey object

        Raises:
            ValueError: If key bytes are not valid
        """
        return cls(key_bytes)

    def __init__(self,
                 key_obj: Any) -> None:
        """
        Construct class from key object.

        Args:
            key_obj (class): Key object

        Raises:
            TypeError: If key object is not of the correct type
            ValueError: If key is not valid
        """
        if not isinstance(key_obj, bytes):
            raise TypeError("Invalid private key object type")
        if not ed25519_monero_lib.is_valid_priv_key(key_obj):
            raise ValueError("Invalid private key")

        self.m_sign_key = key_obj

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519_MONERO

    @staticmethod
    def Length() -> int:
        """
        Get the key length.

        Returns:
           int: Key length
        """
        return Ed25519MoneroKeysConst.PRIV_KEY_BYTE_LEN

    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_sign_key

    def Raw(self) -> DataBytes:
        """
        Return raw private key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_sign_key)

    def PublicKey(self) -> IPublicKey:
        """
        Get the public key correspondent to the private one.

        Returns:
            IPublicKey object: IPublicKey object
        """
        return Ed25519MoneroPublicKey(ed25519_monero_lib.public_from_secret(self.m_sign_key))