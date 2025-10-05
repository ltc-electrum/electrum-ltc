from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class StatusRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class StatusResponse(_message.Message):
    __slots__ = ("block_header_height", "mweb_header_height", "mweb_utxos_height", "block_time")
    BLOCK_HEADER_HEIGHT_FIELD_NUMBER: _ClassVar[int]
    MWEB_HEADER_HEIGHT_FIELD_NUMBER: _ClassVar[int]
    MWEB_UTXOS_HEIGHT_FIELD_NUMBER: _ClassVar[int]
    BLOCK_TIME_FIELD_NUMBER: _ClassVar[int]
    block_header_height: int
    mweb_header_height: int
    mweb_utxos_height: int
    block_time: int
    def __init__(self, block_header_height: _Optional[int] = ..., mweb_header_height: _Optional[int] = ..., mweb_utxos_height: _Optional[int] = ..., block_time: _Optional[int] = ...) -> None: ...

class UtxosRequest(_message.Message):
    __slots__ = ("from_height", "scan_secret")
    FROM_HEIGHT_FIELD_NUMBER: _ClassVar[int]
    SCAN_SECRET_FIELD_NUMBER: _ClassVar[int]
    from_height: int
    scan_secret: bytes
    def __init__(self, from_height: _Optional[int] = ..., scan_secret: _Optional[bytes] = ...) -> None: ...

class Utxo(_message.Message):
    __slots__ = ("height", "value", "address", "output_id", "block_time")
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_ID_FIELD_NUMBER: _ClassVar[int]
    BLOCK_TIME_FIELD_NUMBER: _ClassVar[int]
    height: int
    value: int
    address: str
    output_id: str
    block_time: int
    def __init__(self, height: _Optional[int] = ..., value: _Optional[int] = ..., address: _Optional[str] = ..., output_id: _Optional[str] = ..., block_time: _Optional[int] = ...) -> None: ...

class AddressRequest(_message.Message):
    __slots__ = ("from_index", "to_index", "scan_secret", "spend_pubkey")
    FROM_INDEX_FIELD_NUMBER: _ClassVar[int]
    TO_INDEX_FIELD_NUMBER: _ClassVar[int]
    SCAN_SECRET_FIELD_NUMBER: _ClassVar[int]
    SPEND_PUBKEY_FIELD_NUMBER: _ClassVar[int]
    from_index: int
    to_index: int
    scan_secret: bytes
    spend_pubkey: bytes
    def __init__(self, from_index: _Optional[int] = ..., to_index: _Optional[int] = ..., scan_secret: _Optional[bytes] = ..., spend_pubkey: _Optional[bytes] = ...) -> None: ...

class AddressResponse(_message.Message):
    __slots__ = ("address",)
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, address: _Optional[_Iterable[str]] = ...) -> None: ...

class LedgerApdu(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class SpentRequest(_message.Message):
    __slots__ = ("output_id",)
    OUTPUT_ID_FIELD_NUMBER: _ClassVar[int]
    output_id: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, output_id: _Optional[_Iterable[str]] = ...) -> None: ...

class SpentResponse(_message.Message):
    __slots__ = ("output_id",)
    OUTPUT_ID_FIELD_NUMBER: _ClassVar[int]
    output_id: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, output_id: _Optional[_Iterable[str]] = ...) -> None: ...

class CreateRequest(_message.Message):
    __slots__ = ("raw_tx", "scan_secret", "spend_secret", "fee_rate_per_kb", "dry_run")
    RAW_TX_FIELD_NUMBER: _ClassVar[int]
    SCAN_SECRET_FIELD_NUMBER: _ClassVar[int]
    SPEND_SECRET_FIELD_NUMBER: _ClassVar[int]
    FEE_RATE_PER_KB_FIELD_NUMBER: _ClassVar[int]
    DRY_RUN_FIELD_NUMBER: _ClassVar[int]
    raw_tx: bytes
    scan_secret: bytes
    spend_secret: bytes
    fee_rate_per_kb: int
    dry_run: bool
    def __init__(self, raw_tx: _Optional[bytes] = ..., scan_secret: _Optional[bytes] = ..., spend_secret: _Optional[bytes] = ..., fee_rate_per_kb: _Optional[int] = ..., dry_run: bool = ...) -> None: ...

class CreateResponse(_message.Message):
    __slots__ = ("raw_tx", "output_id")
    RAW_TX_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_ID_FIELD_NUMBER: _ClassVar[int]
    raw_tx: bytes
    output_id: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, raw_tx: _Optional[bytes] = ..., output_id: _Optional[_Iterable[str]] = ...) -> None: ...

class PsbtCreateRequest(_message.Message):
    __slots__ = ("raw_tx", "witness_utxo")
    RAW_TX_FIELD_NUMBER: _ClassVar[int]
    WITNESS_UTXO_FIELD_NUMBER: _ClassVar[int]
    raw_tx: bytes
    witness_utxo: _containers.RepeatedCompositeFieldContainer[TxOut]
    def __init__(self, raw_tx: _Optional[bytes] = ..., witness_utxo: _Optional[_Iterable[_Union[TxOut, _Mapping]]] = ...) -> None: ...

class TxOut(_message.Message):
    __slots__ = ("value", "pk_script")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    PK_SCRIPT_FIELD_NUMBER: _ClassVar[int]
    value: int
    pk_script: bytes
    def __init__(self, value: _Optional[int] = ..., pk_script: _Optional[bytes] = ...) -> None: ...

class PsbtResponse(_message.Message):
    __slots__ = ("psbt_b64",)
    PSBT_B64_FIELD_NUMBER: _ClassVar[int]
    psbt_b64: str
    def __init__(self, psbt_b64: _Optional[str] = ...) -> None: ...

class PsbtAddInputRequest(_message.Message):
    __slots__ = ("psbt_b64", "scan_secret", "output_id", "address_index")
    PSBT_B64_FIELD_NUMBER: _ClassVar[int]
    SCAN_SECRET_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_INDEX_FIELD_NUMBER: _ClassVar[int]
    psbt_b64: str
    scan_secret: bytes
    output_id: str
    address_index: int
    def __init__(self, psbt_b64: _Optional[str] = ..., scan_secret: _Optional[bytes] = ..., output_id: _Optional[str] = ..., address_index: _Optional[int] = ...) -> None: ...

class PsbtAddRecipientRequest(_message.Message):
    __slots__ = ("psbt_b64", "recipient", "fee_rate_per_kb")
    PSBT_B64_FIELD_NUMBER: _ClassVar[int]
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    FEE_RATE_PER_KB_FIELD_NUMBER: _ClassVar[int]
    psbt_b64: str
    recipient: PsbtRecipient
    fee_rate_per_kb: int
    def __init__(self, psbt_b64: _Optional[str] = ..., recipient: _Optional[_Union[PsbtRecipient, _Mapping]] = ..., fee_rate_per_kb: _Optional[int] = ...) -> None: ...

class PsbtGetRecipientsRequest(_message.Message):
    __slots__ = ("psbt_b64",)
    PSBT_B64_FIELD_NUMBER: _ClassVar[int]
    psbt_b64: str
    def __init__(self, psbt_b64: _Optional[str] = ...) -> None: ...

class PsbtGetRecipientsResponse(_message.Message):
    __slots__ = ("recipient", "input_address", "fee")
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    INPUT_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    FEE_FIELD_NUMBER: _ClassVar[int]
    recipient: _containers.RepeatedCompositeFieldContainer[PsbtRecipient]
    input_address: _containers.RepeatedScalarFieldContainer[str]
    fee: int
    def __init__(self, recipient: _Optional[_Iterable[_Union[PsbtRecipient, _Mapping]]] = ..., input_address: _Optional[_Iterable[str]] = ..., fee: _Optional[int] = ...) -> None: ...

class PsbtRecipient(_message.Message):
    __slots__ = ("address", "value")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    address: str
    value: int
    def __init__(self, address: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...

class PsbtSignRequest(_message.Message):
    __slots__ = ("psbt_b64", "scan_secret", "spend_secret")
    PSBT_B64_FIELD_NUMBER: _ClassVar[int]
    SCAN_SECRET_FIELD_NUMBER: _ClassVar[int]
    SPEND_SECRET_FIELD_NUMBER: _ClassVar[int]
    psbt_b64: str
    scan_secret: bytes
    spend_secret: bytes
    def __init__(self, psbt_b64: _Optional[str] = ..., scan_secret: _Optional[bytes] = ..., spend_secret: _Optional[bytes] = ...) -> None: ...

class PsbtSignNonMwebRequest(_message.Message):
    __slots__ = ("psbt_b64", "priv_key", "index")
    PSBT_B64_FIELD_NUMBER: _ClassVar[int]
    PRIV_KEY_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    psbt_b64: str
    priv_key: bytes
    index: int
    def __init__(self, psbt_b64: _Optional[str] = ..., priv_key: _Optional[bytes] = ..., index: _Optional[int] = ...) -> None: ...

class PsbtExtractRequest(_message.Message):
    __slots__ = ("psbt_b64", "unsigned")
    PSBT_B64_FIELD_NUMBER: _ClassVar[int]
    UNSIGNED_FIELD_NUMBER: _ClassVar[int]
    psbt_b64: str
    unsigned: bool
    def __init__(self, psbt_b64: _Optional[str] = ..., unsigned: bool = ...) -> None: ...

class BroadcastRequest(_message.Message):
    __slots__ = ("raw_tx",)
    RAW_TX_FIELD_NUMBER: _ClassVar[int]
    raw_tx: bytes
    def __init__(self, raw_tx: _Optional[bytes] = ...) -> None: ...

class BroadcastResponse(_message.Message):
    __slots__ = ("txid",)
    TXID_FIELD_NUMBER: _ClassVar[int]
    txid: str
    def __init__(self, txid: _Optional[str] = ...) -> None: ...

class CoinswapRequest(_message.Message):
    __slots__ = ("scan_secret", "spend_secret", "output_id", "addr_index")
    SCAN_SECRET_FIELD_NUMBER: _ClassVar[int]
    SPEND_SECRET_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_ID_FIELD_NUMBER: _ClassVar[int]
    ADDR_INDEX_FIELD_NUMBER: _ClassVar[int]
    scan_secret: bytes
    spend_secret: bytes
    output_id: str
    addr_index: int
    def __init__(self, scan_secret: _Optional[bytes] = ..., spend_secret: _Optional[bytes] = ..., output_id: _Optional[str] = ..., addr_index: _Optional[int] = ...) -> None: ...

class CoinswapResponse(_message.Message):
    __slots__ = ("output_id",)
    OUTPUT_ID_FIELD_NUMBER: _ClassVar[int]
    output_id: str
    def __init__(self, output_id: _Optional[str] = ...) -> None: ...
