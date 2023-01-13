#!/usr/bin/env python3
# Copyright (c) 2021 The PLC Ultima Classic Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.key import create_key
from test_framework.blocktools import create_coinbase, create_block
from test_framework.certs import send_block

'''
coinbase_subsidy.py
'''

FEE_REDUCTION_BLOCK = 250  # CChainParams::feeReductionBlock() in cpp
FEE_QUARTERING_BLOCK = 300  # CChainParams::feeQuarteringBlock() in cpp

# TestNode: bare-bones "peer".
class TestNode(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.reject_message = None

    def add_connection(self, conn):
        self.connection = conn
        self.peer_disconnected = False

    def on_close(self, conn):
        self.peer_disconnected = True

    def wait_for_disconnect(self):
        def disconnected():
            return self.peer_disconnected
        return wait_until(disconnected, timeout=10)

    def on_reject(self, conn, message):
        self.reject_message = message


class CoinbaseSubsidyTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-debug', '-whitelist=127.0.0.1', f'-feereductionblock-regtest={FEE_REDUCTION_BLOCK}',
                            f'-feequarteringblock-regtest={FEE_QUARTERING_BLOCK}']]
        self.outpoints = []


    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()


    def create_tx_with_fee(self, fee):
        outpoint = self.outpoints.pop(0)
        (burn1, burn2, change) = BurnedAndChangeAmount(ToCoins(self.outpoint_amount) - ToCoins(fee))
        tx1 = CTransaction()
        tx1.vin.append(CTxIn(outpoint, self.my_p2pkh_scriptpubkey, 0xffffffff))
        tx1.vout = []
        tx1.vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(hash160(b'some_address'))))
        tx1.vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
        tx1.vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
        (sig_hash, err) = SignatureHash(self.my_p2pkh_scriptpubkey, tx1, 0, SIGHASH_ALL)
        assert (err is None)
        signature = self.my_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx1.vin[0].scriptSig = CScript([signature, self.my_pubkey])
        return tx1


    def compose_and_send_block(self, coinbase, tx_list, accepted, reject_reasons=[]):
        coinbase.rehash()
        for tx in tx_list:
            tx.rehash()
        tmpl = self.nodes[0].getblocktemplate()
        block = create_block(int(tmpl['previousblockhash'], 16), coinbase, tmpl['curtime'], int(tmpl['bits'], 16), VB_TOP_BITS, tx_list)
        self.log.debug(f'block: {block}')
        send_block(self.nodes[0], self.test_node, block, accepted, reject_reasons)


    def generate_outpoints(self):
        amount = self.outpoint_amount
        fee = Decimal('0.00001000')
        (burn1, burn2, change) = BurnedAndChangeAmount(amount - fee)
        self.log.debug(f'amount: {amount}, fee: {fee}, burn1: {burn1}, burn2: {burn2}, change: {change}')
        for i in range(80):
            txid = self.nodes[0].sendtoaddress(AddressFromPubkeyHash(self.my_pkh), amount)
            verify_tx_sent(self.nodes[0], txid)
            self.outpoints.append(COutPoint(int(txid, 16), find_output(self.nodes[0], txid, amount)))


    def run_test(self):
        self.my_key = create_key(True)
        self.my_pubkey = self.my_key.get_pubkey()
        self.my_pkh = hash160(self.my_pubkey)
        self.my_p2pkh_scriptpubkey = GetP2PKHScript(self.my_pkh)
        self.my_p2pk_scriptpubkey = CScript([self.my_pubkey, OP_CHECKSIG])
        cb_pubkey = self.my_pubkey

        node0 = self.nodes[0]
        height = 50
        node0.generate(height)
        self.test_node.sync_with_ping()
        assert_equal(node0.getblockcount(), height)

        # A series
        # (0 < height <= 100)

        # A-01
        # normal coinbase: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        assert_equal(cb.vout[0].nValue, ToSatoshi(BASE_CB_AMOUNT))
        self.compose_and_send_block(cb, [], True)
        moneybox_vout = cb.vout[-1]

        # A-02
        # coinbase subsidy is less than allowed: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[0].nValue -= 1
        self.compose_and_send_block(cb, [], True)

        # A-03
        # coinbase subsidy is more than allowed: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[0].nValue += 1
        self.compose_and_send_block(cb, [], False, ['bad-cb-amount'])

        # A-04
        # moneybox refill is less than required: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[1].nValue -= 1
        self.compose_and_send_block(cb, [], False, ['bad-box-amount'])

        # A-05
        # moneybox refill is more than required (and more than granularity): rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[1].nValue += 1
        self.compose_and_send_block(cb, [], False, ['bad-txns-moneybox-value-toolarge'])

        # A-06
        # moneybox refill is more than required in one output (and more than granularity) and less in another, summary OK: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[1].nValue += 1
        cb.vout[2].nValue -= 1
        self.compose_and_send_block(cb, [], False, ['bad-txns-moneybox-value-toolarge'])

        # A-07
        # moneybox refill is more than required (has an extra output, granularity is OK): rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout.append(CTxOut(1 * COIN, cb.vout[-1].scriptPubKey))
        self.compose_and_send_block(cb, [], False, ['bad-box-amount'])

        # A-08
        # moneybox refill is less than required in one output, but has extra output with this amount, summary OK: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        delta = 1 * COIN
        cb.vout[1].nValue -= delta
        cb.vout.append(CTxOut(delta, cb.vout[-1].scriptPubKey))
        self.compose_and_send_block(cb, [], True)

        # A-09
        # moneybox refill is less than required in 2 outputs, but has 2 extra outputs with this amount, summary OK: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        delta = 1 * COIN
        cb.vout[1].nValue -= delta
        cb.vout[2].nValue -= delta
        cb.vout.append(CTxOut(delta, cb.vout[-1].scriptPubKey))
        cb.vout.append(CTxOut(delta, cb.vout[-1].scriptPubKey))
        self.compose_and_send_block(cb, [], False, ['bad-box-count'])

        node0.generate(100)
        self.outpoint_amount = Decimal(10)
        self.generate_outpoints()
        node0.generate(1)

        # B series
        # (100 < height <= FEE_REDUCTION_BLOCK)

        fee1 = ToSatoshi(CB_AMOUNT_AFTER_BLOCK_100 * 6 / 10)  # 0.003
        fee2 = ToSatoshi(CB_AMOUNT_AFTER_BLOCK_100 * 8 / 10)  # 0.004
        fee3 = ToSatoshi(CB_AMOUNT_AFTER_BLOCK_100 * 12 / 10)  # 0.006
        fee4 = ToSatoshi(CB_AMOUNT_AFTER_BLOCK_100 * 14 / 10)  # 0.007

        # B-01
        # normal coinbase without other transactions: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        assert_equal(cb.vout[0].nValue, ToSatoshi(CB_AMOUNT_AFTER_BLOCK_100))
        self.compose_and_send_block(cb, [], True)

        # B-02
        # without other transactions
        # coinbase subsidy is less than allowed: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[0].nValue -= 1
        self.compose_and_send_block(cb, [], True)

        # B-03
        # without other transactions
        # coinbase subsidy is more than allowed: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[0].nValue += 1
        self.compose_and_send_block(cb, [], False, ['bad-cb-amount'])

        # B-04
        # (sum(tx_fees) / 2 < CB_AMOUNT_AFTER_BLOCK_100): CB_AMOUNT_AFTER_BLOCK_100 is used: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        assert_equal(cb.vout[0].nValue, ToSatoshi(CB_AMOUNT_AFTER_BLOCK_100))
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], True)

        # B-05
        # (sum(tx_fees) / 2 < CB_AMOUNT_AFTER_BLOCK_100): CB_AMOUNT_AFTER_BLOCK_100 must be used, try 1 satoshi more: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        assert_equal(cb.vout[0].nValue, ToSatoshi(CB_AMOUNT_AFTER_BLOCK_100))
        cb.vout[0].nValue += 1
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], False, ['bad-cb-amount'])

        # B-06
        # (sum(tx_fees) / 2 > CB_AMOUNT_AFTER_BLOCK_100): sum(tx_fees) / 2 is used: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee3 + fee4)
        assert_equal(cb.vout[0].nValue, (fee3 + fee4) // 2)
        tx3 = self.create_tx_with_fee(fee3)
        tx4 = self.create_tx_with_fee(fee4)
        self.compose_and_send_block(cb, [tx3, tx4], True)

        # B-07
        # (sum(tx_fees) / 2 > CB_AMOUNT_AFTER_BLOCK_100): sum(tx_fees) / 2 must be used, try 1 satoshi more: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee3 + fee4)
        assert_equal(cb.vout[0].nValue, (fee3 + fee4) // 2)
        cb.vout[0].nValue += 1
        tx3 = self.create_tx_with_fee(fee3)
        tx4 = self.create_tx_with_fee(fee4)
        self.compose_and_send_block(cb, [tx3, tx4], False, ['bad-cb-amount'])

        # B-08
        # without other transactions
        # try to fill up moneybox: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        moneybox_vout.nValue = ToSatoshi(CB_AMOUNT_AFTER_BLOCK_100)
        cb.vout.append(moneybox_vout)
        self.compose_and_send_block(cb, [], False, ['bad-box-amount', 'bad-cb-amount'])

        # B-09
        # with normal transactions not spending moneybox
        # try to fill up moneybox: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee3 + fee4)
        cb.vout.append(moneybox_vout)
        tx3 = self.create_tx_with_fee(fee3)
        tx4 = self.create_tx_with_fee(fee4)
        self.compose_and_send_block(cb, [tx3, tx4], False, ['bad-box-amount', 'bad-cb-amount'])

        # B-10
        # Case B-04 with txs with (fee1, fee2), but compose a block as if we reached FEE_QUARTERING_BLOCK: accepted
        # (not forbidden to send block fee to mausoleum)
        height = node0.getblockcount()
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2,
                             fee_reduction_block=height - 2, fee_quartering_block=height - 1)
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], True)

        # B-11
        # Case B-06 with txs with (fee3, fee4), but compose a block as if we reached FEE_QUARTERING_BLOCK: accepted
        # (not forbidden to send block fee to mausoleum)
        height = node0.getblockcount()
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee3 + fee4,
                             fee_reduction_block=height - 2, fee_quartering_block=height - 1)
        tx3 = self.create_tx_with_fee(fee3)
        tx4 = self.create_tx_with_fee(fee4)
        self.compose_and_send_block(cb, [tx3, tx4], True)

        # C series
        # (FEE_REDUCTION_BLOCK < height <= FEE_QUARTERING_BLOCK)

        generate_many_blocks(node0, FEE_REDUCTION_BLOCK + 1 - node0.getblockcount())
        fee1 = ToSatoshi(CB_AMOUNT_AFTER_REDUCTION * 6 / 10)  # 0.00003
        fee2 = ToSatoshi(CB_AMOUNT_AFTER_REDUCTION * 8 / 10)  # 0.00004
        fee3 = ToSatoshi(CB_AMOUNT_AFTER_REDUCTION * 12 / 10)  # 0.00006
        fee4 = ToSatoshi(CB_AMOUNT_AFTER_REDUCTION * 14 / 10)  # 0.00007
        fee5 = ToSatoshi(CB_AMOUNT_AFTER_REDUCTION * 22 / 10)  # 0.00011
        fee6 = ToSatoshi(CB_AMOUNT_AFTER_REDUCTION * 24 / 10)  # 0.00012

        # C-01
        # normal coinbase without other transactions: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee_reduction_block=FEE_REDUCTION_BLOCK)
        assert_equal(cb.vout[0].nValue, ToSatoshi(CB_AMOUNT_AFTER_REDUCTION))
        self.compose_and_send_block(cb, [], True)

        # C-02
        # without other transactions
        # coinbase subsidy is less than allowed: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee_reduction_block=FEE_REDUCTION_BLOCK)
        cb.vout[0].nValue -= 1
        self.compose_and_send_block(cb, [], True)

        # C-03
        # without other transactions
        # coinbase subsidy is more than allowed: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee_reduction_block=FEE_REDUCTION_BLOCK)
        cb.vout[0].nValue += 1
        self.compose_and_send_block(cb, [], False, ['bad-cb-amount'])

        # C-04
        # (sum(tx_fees) / 2 < CB_AMOUNT_AFTER_REDUCTION): CB_AMOUNT_AFTER_REDUCTION is used: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2, fee_reduction_block=FEE_REDUCTION_BLOCK)
        assert_equal(cb.vout[0].nValue, ToSatoshi(CB_AMOUNT_AFTER_REDUCTION))
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], True)

        # C-05
        # (sum(tx_fees) / 2 < CB_AMOUNT_AFTER_REDUCTION): CB_AMOUNT_AFTER_REDUCTION must be used, try 1 satoshi more: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2, fee_reduction_block=FEE_REDUCTION_BLOCK)
        assert_equal(cb.vout[0].nValue, ToSatoshi(CB_AMOUNT_AFTER_REDUCTION))
        cb.vout[0].nValue += 1
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], False, ['bad-cb-amount'])

        # C-06
        # (sum(tx_fees) / 2 > CB_AMOUNT_AFTER_REDUCTION): sum(tx_fees) / 2 is used: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee3 + fee4, fee_reduction_block=FEE_REDUCTION_BLOCK)
        assert_equal(cb.vout[0].nValue, (fee3 + fee4) // 2)
        tx3 = self.create_tx_with_fee(fee3)
        tx4 = self.create_tx_with_fee(fee4)
        self.compose_and_send_block(cb, [tx3, tx4], True)

        # C-07
        # (sum(tx_fees) / 2 > CB_AMOUNT_AFTER_REDUCTION): sum(tx_fees) / 2 must be used, try 1 satoshi more: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee3 + fee4, fee_reduction_block=FEE_REDUCTION_BLOCK)
        assert_equal(cb.vout[0].nValue, (fee3 + fee4) // 2)
        cb.vout[0].nValue += 1
        tx3 = self.create_tx_with_fee(fee3)
        tx4 = self.create_tx_with_fee(fee4)
        self.compose_and_send_block(cb, [tx3, tx4], False, ['bad-cb-amount'])

        # C-08
        # without other transactions
        # try to fill up moneybox: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee_reduction_block=FEE_REDUCTION_BLOCK)
        moneybox_vout.nValue = ToSatoshi(CB_AMOUNT_AFTER_REDUCTION)
        cb.vout.append(moneybox_vout)
        self.compose_and_send_block(cb, [], False, ['bad-box-amount', 'bad-cb-amount'])

        # C-09
        # with normal transactions not spending moneybox
        # try to fill up moneybox: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee3 + fee4, fee_reduction_block=FEE_REDUCTION_BLOCK)
        cb.vout.append(moneybox_vout)
        tx3 = self.create_tx_with_fee(fee3)
        tx4 = self.create_tx_with_fee(fee4)
        self.compose_and_send_block(cb, [tx3, tx4], False, ['bad-box-amount', 'bad-cb-amount'])

        # C-10
        # Case C-04 with txs with (fee1, fee2), but compose a block as if we reached FEE_QUARTERING_BLOCK: accepted
        # (not forbidden to send block fee to mausoleum)
        height = node0.getblockcount()
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2,
                             fee_reduction_block=FEE_REDUCTION_BLOCK, fee_quartering_block=height - 1)
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], True)

        # C-11
        # Case C-06 with txs with (fee3, fee4), but compose a block as if we reached FEE_QUARTERING_BLOCK: accepted
        # (not forbidden to send block fee to mausoleum)
        height = node0.getblockcount()
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee3 + fee4,
                             fee_reduction_block=FEE_REDUCTION_BLOCK, fee_quartering_block=height - 1)
        tx3 = self.create_tx_with_fee(fee3)
        tx4 = self.create_tx_with_fee(fee4)
        self.compose_and_send_block(cb, [tx3, tx4], True)

        # C-12
        # Case with txs with (fee5, fee6), but compose a block as if we reached FEE_QUARTERING_BLOCK: accepted
        # (not forbidden to send block fee to mausoleum)
        height = node0.getblockcount()
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee3 + fee4,
                             fee_reduction_block=FEE_REDUCTION_BLOCK, fee_quartering_block=height - 1)
        tx5 = self.create_tx_with_fee(fee5)
        tx6 = self.create_tx_with_fee(fee6)
        self.compose_and_send_block(cb, [tx5, tx6], True)

        # D series
        # (height > FEE_QUARTERING_BLOCK)

        generate_many_blocks(node0, FEE_QUARTERING_BLOCK + 1 - node0.getblockcount())

        # D-01
        # normal coinbase without other transactions: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee_reduction_block=FEE_REDUCTION_BLOCK,
                             fee_quartering_block=FEE_QUARTERING_BLOCK)
        assert_equal(cb.vout[0].nValue, ToSatoshi(CB_AMOUNT_AFTER_REDUCTION))
        self.compose_and_send_block(cb, [], True)

        # D-02
        # without other transactions
        # coinbase subsidy is less than allowed: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee_reduction_block=FEE_REDUCTION_BLOCK,
                             fee_quartering_block=FEE_QUARTERING_BLOCK)
        cb.vout[0].nValue -= 1
        self.compose_and_send_block(cb, [], True)

        # D-03
        # without other transactions
        # coinbase subsidy is more than allowed: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee_reduction_block=FEE_REDUCTION_BLOCK,
                             fee_quartering_block=FEE_QUARTERING_BLOCK)
        cb.vout[0].nValue += 1
        self.compose_and_send_block(cb, [], False, ['bad-cb-amount'])

        # D-08
        # without other transactions
        # try to fill up moneybox: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee_reduction_block=FEE_REDUCTION_BLOCK,
                             fee_quartering_block=FEE_QUARTERING_BLOCK)
        moneybox_vout.nValue = ToSatoshi(CB_AMOUNT_AFTER_REDUCTION)
        cb.vout.append(moneybox_vout)
        self.compose_and_send_block(cb, [], False, ['bad-box-amount', 'bad-cb-amount'])

        # D-09
        # with normal transactions not spending moneybox
        # try to fill up moneybox: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2, fee_reduction_block=FEE_REDUCTION_BLOCK,
                             fee_quartering_block=FEE_QUARTERING_BLOCK)
        cb.vout.append(moneybox_vout)
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], False, ['bad-box-amount', 'bad-cb-amount'])


        #                |  add_mausoleum_output  |  add_mausoleum_output  |  old behavior  |
        #                |          True          |          False         |                |
        # ---------------|------------------------|------------------------|----------------|
        #   (fee1, fee2) |      accepted          |      rejected          |    rejected    |
        #   (fee3, fee4) |      accepted          |      rejected          |    rejected    |
        #   (fee5, fee6) |      accepted          |      rejected          |    rejected    |
        # ---------------|------------------------|------------------------|----------------|
        #
        expected_results = \
        {
            (fee1, fee2): {True: True, False: False, 'old_behavior': False},
            (fee3, fee4): {True: True, False: False, 'old_behavior': False},
            (fee5, fee6): {True: True, False: False, 'old_behavior': False},
        }

        for fees in [(fee1, fee2), (fee3, fee4), (fee5, fee6)]:
            (feeA, feeB) = fees
            for force_add_mausoleum_output in [True, False]:
                cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, feeA + feeB,
                                     fee_reduction_block=FEE_REDUCTION_BLOCK,
                                     fee_quartering_block=FEE_QUARTERING_BLOCK,
                                     force_add_mausoleum_output=force_add_mausoleum_output)
                txA = self.create_tx_with_fee(feeA)
                txB = self.create_tx_with_fee(feeB)
                accepted = expected_results[fees][force_add_mausoleum_output]
                self.log.debug(f'Will compose_and_send_block with: fees: {fees}, '
                               f'force_add_mausoleum_output: {force_add_mausoleum_output}, accepted: {accepted}')
                self.compose_and_send_block(cb, [txA, txB], accepted, ['bad-cb-burned'])

            # Try old_behavior, as if we didn't reach FEE_QUARTERING_BLOCK:
            cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, feeA + feeB,
                                 fee_reduction_block=FEE_REDUCTION_BLOCK,
                                 fee_quartering_block=FEE_QUARTERING_BLOCK + 100)
            txA = self.create_tx_with_fee(feeA)
            txB = self.create_tx_with_fee(feeB)
            accepted = expected_results[fees]['old_behavior']
            self.log.debug(f'Will compose_and_send_block with: fees: {fees}, old_behavior, accepted: {accepted}')
            self.compose_and_send_block(cb, [txA, txB], accepted, ['bad-cb-amount', 'bad-cb-burned'])

            # Try 1 satoshi more to miner reward: rejected
            cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, feeA + feeB,
                                 fee_reduction_block=FEE_REDUCTION_BLOCK,
                                 fee_quartering_block=FEE_QUARTERING_BLOCK)
            cb.vout[0].nValue += 1
            txA = self.create_tx_with_fee(feeA)
            txB = self.create_tx_with_fee(feeB)
            self.log.debug(f'Will compose_and_send_block with: fees: {fees}, 1 satoshi more to miner reward, rejected')
            self.compose_and_send_block(cb, [txA, txB], False, ['bad-cb-amount'])

            # Try 1 satoshi more to miner reward, and 1 satoshi less to mausoleum: rejected
            cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, feeA + feeB,
                                 fee_reduction_block=FEE_REDUCTION_BLOCK,
                                 fee_quartering_block=FEE_QUARTERING_BLOCK,
                                 force_add_mausoleum_output=True)
            cb.vout[0].nValue += 1
            cb.vout[1].nValue -= 1
            txA = self.create_tx_with_fee(feeA)
            txB = self.create_tx_with_fee(feeB)
            self.log.debug(f'Will compose_and_send_block with: fees: {fees}, 1 satoshi more to miner reward, '
                           f'and 1 satoshi less to mausoleum, rejected')
            self.compose_and_send_block(cb, [txA, txB], False, ['bad-cb-amount'])

            # Try 1 satoshi less to mausoleum:
            cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, feeA + feeB,
                                 fee_reduction_block=FEE_REDUCTION_BLOCK,
                                 fee_quartering_block=FEE_QUARTERING_BLOCK,
                                 force_add_mausoleum_output=True)
            cb.vout[1].nValue -= 1
            txA = self.create_tx_with_fee(feeA)
            txB = self.create_tx_with_fee(feeB)
            accepted = expected_results[fees][False]
            self.log.debug(f'Will compose_and_send_block with: fees: {fees}, 1 satoshi less to mausoleum, accepted: {accepted}')
            self.compose_and_send_block(cb, [txA, txB], accepted, ['bad-cb-burned'])


if __name__ == '__main__':
    CoinbaseSubsidyTest().main()
