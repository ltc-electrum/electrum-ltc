from base64 import b64decode, b64encode
from PyQt6.QtCore import pyqtSignal

from electrum.bitcoin import is_mweb_address
from electrum.gui.qt.qrreader import scan_qrcode_from_camera
from electrum.hw_wallet.qt import QtHandlerBase
from electrum.keystore import Cupcake_KeyStore
from electrum.mwebd import stub
from electrum.mwebd_pb2 import (
    PsbtAddInputRequest,
    PsbtAddRecipientRequest,
    PsbtCreateRequest,
    PsbtExtractRequest,
    PsbtRecipient,
    TxOut,
)
from electrum.plugin import BasePlugin, hook
from electrum.transaction import PartialTransaction, Transaction
from electrum.ur.cbor_lite import CBORDecoder, CBOREncoder
from electrum.ur.ur import UR
from electrum.ur.ur_encoder import UREncoder
from electrum.util import partition, UserFacingException

class Plugin(BasePlugin):
    @hook
    def load_wallet(self, wallet, win):
        for k in wallet.get_keystores():
            if isinstance(k, Cupcake_KeyStore):
                k.handler = Handler(win)

class Handler(QtHandlerBase):

    show_ur_signal = pyqtSignal(object)

    def __init__(self, win):
        super().__init__(win, 'Cupcake')
        self.show_ur_signal.connect(self.show_ur)

    def sign_transaction(self, keystore: Cupcake_KeyStore, tx: PartialTransaction):
        mwins, ins = partition(lambda x: x.mweb_output_id, tx.inputs())
        chng, outs = partition(lambda x: not is_mweb_address(x.address) and x.is_change, tx.outputs())
        tx2 = PartialTransaction.from_io(ins, chng, locktime=tx.locktime)
        raw_tx = bytes.fromhex(tx2.serialize_to_network(include_sigs=False)) if ins else None
        utxos = [TxOut(value=x.value_sats(), pk_script=x.scriptpubkey) for x in ins]
        resp = stub().PsbtCreate(PsbtCreateRequest(raw_tx=raw_tx, witness_utxo=utxos))
        for txin in mwins:
            resp = stub().PsbtAddInput(PsbtAddInputRequest(
                psbt_b64=resp.psbt_b64,
                scan_secret=bytes.fromhex(keystore.scan_secret),
                output_id=txin.mweb_output_id,
                address_index=txin.mweb_address_index))
        for txout in outs:
            resp = stub().PsbtAddRecipient(PsbtAddRecipientRequest(
                psbt_b64=resp.psbt_b64,
                recipient=PsbtRecipient(address=txout.address, value=txout.value),
                fee_rate_per_kb=tx._fee_estimator(1000)))
        cbor_enc = CBOREncoder()
        cbor_enc.encodeBytes(b64decode(resp.psbt_b64))
        ur_enc = UREncoder(UR('psbt', cbor_enc.get_bytes()), 120)
        data = []
        while not ur_enc.is_complete():
            data.append(ur_enc.next_part())
        self.done.clear()
        self.show_ur_signal.emit(data)
        self.done.wait()
        if not isinstance(self.result, UR) or self.result.type != 'psbt':
            raise UserFacingException('Did not scan a UR PSBT')
        cbor_dec = CBORDecoder(self.result.cbor)
        data, _ = cbor_dec.decodeBytes()
        resp = stub().PsbtExtract(PsbtExtractRequest(psbt_b64=b64encode(data).decode()))
        for txout in tx.outputs():
            if is_mweb_address(txout.address):
                txout.mweb_output_id = resp.output_id.pop(0)
        tx2 = PartialTransaction.from_tx(Transaction(resp.raw_tx), strip_witness=False)
        for x in ('_inputs', '_outputs', '_extra_bytes'):
            setattr(tx, x, getattr(tx2, x))

    def show_ur(self, data):
        self.win.show_qrcode(data, parent=self.top_level_window())
        def cb(success, error, data):
            if error: self.show_error(error, True)
            self.result = data
            self.done.set()
        scan_qrcode_from_camera(parent=self.top_level_window(), config=self.win.config, callback=cb)
