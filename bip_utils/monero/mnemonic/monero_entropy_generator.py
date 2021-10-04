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


# Imports
from enum import IntEnum, unique
from typing import List, Union
from bip_utils.utils.mnemonic import EntropyGenerator


@unique
class MoneroEntropyBitLen(IntEnum):
    """ Enumerative for Monero entropy bit lengths. """

    BIT_LEN_128 = 128,
    BIT_LEN_256 = 256,


class MoneroEntropyGeneratorConst:
    """ Class container for Monero entropy generator constants. """

    # Accepted entropy lengths in bit
    ENTROPY_BIT_LEN: List[MoneroEntropyBitLen] = [
        MoneroEntropyBitLen.BIT_LEN_128,
        MoneroEntropyBitLen.BIT_LEN_256,
    ]


class MoneroEntropyGenerator(EntropyGenerator):
    """ Entropy generator class. It generates random entropy bytes with the specified length. """

    def __init__(self,
                 bits_len: Union[int, MoneroEntropyBitLen]) -> None:
        """ Construct class by specifying the bits length.

        Args:
            bits_len (int or MoneroEntropyBitLen): Entropy length in bits

        Raises:
            ValueError: If the bit length is not valid
        """
        if not self.IsValidEntropyBitLen(bits_len):
            raise ValueError(f"Entropy bit length is not valid ({bits_len})")
        super().__init__(bits_len // 8)

    @staticmethod
    def IsValidEntropyBitLen(bits_len: Union[int, MoneroEntropyBitLen]) -> bool:
        """ Get if the specified entropy bit length is valid.

        Args:
            bits_len (int or MoneroEntropyBitLen): Entropy length in bits

        Returns:
            bool: True if valid, false otherwise
        """
        return bits_len in MoneroEntropyGeneratorConst.ENTROPY_BIT_LEN

    @staticmethod
    def IsValidEntropyByteLen(bytes_len: int) -> bool:
        """ Get if the specified entropy byte length is valid.

        Args:
            bytes_len (int): Entropy length in bytes

        Returns:
            bool: True if valid, false otherwise
        """
        return MoneroEntropyGenerator.IsValidEntropyBitLen(bytes_len * 8)
