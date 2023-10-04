from typing import Any, Union

from bip_utils.addr.addr_dec_utils import AddrDecUtils
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.eth_addr import EthAddrEncoder, EthAddrConst
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.bech32 import Bech32ChecksumError, Bech32Decoder, Bech32Encoder
from bip_utils.coin_conf.coins_conf import CoinsConf
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import BytesUtils


class CantoAddrDecoder(IAddrDecoder):
    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        try:
            addr_dec_bytes = Bech32Decoder.Decode(
                CoinsConf.Canto.ParamByKey("addr_hrp"),
                addr
            )
        except Bech32ChecksumError as ex:
            raise ValueError("Invalid bech32 checksum") from ex

        AddrDecUtils.ValidateLength(addr_dec_bytes,
                                    EthAddrConst.ADDR_LEN // 2)
        return addr_dec_bytes


class CantoAddrEncoder(IAddrEncoder):
    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        pub_key_obj = AddrKeyValidator.ValidateAndGetSecp256k1Key(pub_key)
        eth_addr = EthAddrEncoder.EncodeKey(pub_key_obj)
        return Bech32Encoder.Encode(CoinsConf.Canto.ParamByKey("addr_hrp"),
                                    BytesUtils.FromHexString(eth_addr[2:]))


# Deprecated: only for compatibility, Encoder class shall be used instead
CantoAddr = CantoAddrEncoder
