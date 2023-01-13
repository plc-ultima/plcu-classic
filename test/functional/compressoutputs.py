#!/usr/bin/env python3
# Copyright (c) 2022 The PLC Ultima Classic Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from parse import parse
from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.certs import *

'''
compressoutputs.py
'''

fee = Decimal('0.00000500')


def utxos_from_blocks(node, blockhashes):
    utxos = []
    for blockhash in blockhashes:
        block = node.getblock(blockhash, 2)
        tx = block['tx'][0]
        txid = tx['txid']
        vout = [v for v in tx['vout'] if v['value'] > 0]
        assert_equal(len(vout), 1)
        utxos.append((txid, vout[0]['n']))
    return utxos


def spend_inputs(node, utxos, amount):
    inputs = [{'txid': t, 'vout': n} for (t, n) in utxos]
    outputs = {GRAVE_ADDRESS_1: amount - fee}
    tx_raw = node.createrawtransaction(inputs, outputs)
    tx_signed = node.signrawtransaction(tx_raw)
    tx_sent = node.sendrawtransaction(tx_signed['hex'])
    verify_tx_sent(node, tx_sent)


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


class CompressOutputsTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [['-debug', '-whitelist=127.0.0.1', '-acceptnonstdtxn=0']] * self.num_nodes
        self.base_small_amount = Decimal('0.00010000')
        self.miner_address = None


    def add_options(self, parser):
        parser.add_option("--withcert", dest="withcert", default=False, action="store_true",
                          help="With tax-free cert")


    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(1), self.nodes[1], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()


    def prepare_empty_node0(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        balance = node0.getbalance()
        unspents = node0.listunspent()
        mempool = node0.getrawmempool()
        self.log.debug(f'prepare_empty_node0, balance: {balance}, unspents: {len(unspents)}, mempool: {len(mempool)}')
        if balance:
            txid = node0.sendtoaddress(node1.getnewaddress(), balance, '', '', True)
            verify_tx_sent(node0, txid)
            node0.generatetoaddress(1, self.miner_address)
        assert_equal(node0.listunspent(), [])
        assert_equal(node0.getbalance(), 0)
        self.log.debug(f'prepare_empty_node0 done')


    def create_inputs(self, node, address, inputs_cnt, amounts, utxos):
        inputs_cnt_left = inputs_cnt
        sent_tx_cnt = 0
        while inputs_cnt_left > 0:
            tx = CTransaction()
            scriptpubkey = hex_str_to_bytes(node.validateaddress(address)['scriptPubKey'])
            next_portion = min(inputs_cnt_left, 200)
            for i in range(next_portion):
                amount = self.base_small_amount + ToCoins(random.randint(0, ToSatoshi(self.base_small_amount) // 2))
                amounts.append(amount)
                tx.vout.append(CTxOut(ToSatoshi(amount), scriptpubkey))
            tx_hex = bytes_to_hex_str(tx.serialize())
            funded = node.fundrawtransaction(tx_hex)
            signed = node.signrawtransaction(funded['hex'])
            tx_id_sent = node.sendrawtransaction(signed['hex'])
            verify_tx_sent(node, tx_id_sent)
            sent_tx_cnt += 1
            if sent_tx_cnt % 25 == 0:
                node.generate(1)
            for i in range(next_portion + 1):
                if i != funded['changepos']:
                    utxos.append((tx_id_sent, i))
            inputs_cnt_left -= next_portion
        if inputs_cnt:
            node.generate(1)


    def check_compressoutputs(self, dest_addr, inputs_cnt_per_tx, taxfree, send_tx, mine, inputs_cnt_normal,
                              inputs_cnt_others, inputs_cnt_exist=0, amount_exist=0, utxos_exist=[], address=None,
                              keep_utxos=False):
        self.log.info(f'Running check_compressoutputs, dest_addr: {dest_addr}, inputs_cnt_per_tx: {inputs_cnt_per_tx}, '
                      f'taxfree: {taxfree}, send_tx: {send_tx}, mine: {mine}, inputs_cnt_total: {inputs_cnt_normal}, '
                      f'inputs_cnt_others: {inputs_cnt_others}, inputs_cnt_exist: {inputs_cnt_exist}, '
                      f'amount_exist: {amount_exist}, utxos_exist: {len(utxos_exist)}, address: {address}, '
                      f'keep_utxos: {keep_utxos}')

        if mine:
            self.log.info(f'Temp skip check for compressmineoutputs')
            return

        node0 = self.nodes[0]
        node1 = self.nodes[1]
        outputs_cnt_expected = 3 if taxfree == False else 1

        if not keep_utxos:
            self.node0_address1 = address if address else node0.getnewaddress()
            self.node0_address2 = node0.getnewaddress()
            self.amounts = []
            self.utxos = []
            self.create_inputs(node1, self.node0_address1, inputs_cnt_normal, self.amounts, self.utxos)
            self.create_inputs(node1, self.node0_address2, inputs_cnt_others, self.amounts if mine else [],
                               self.utxos if mine else [])
            self.log.debug(f'amounts ({len(self.amounts)}): {self.amounts[:500]}')
            if inputs_cnt_normal or inputs_cnt_others:
                node1.generate(6)  # make utxos mature with 6 confirmations

        if taxfree is None:
            dest_addr = self.node0_address1
            taxfree = False

        self.sync_all()
        utxo_set = set(self.utxos + utxos_exist)
        dest_script = hex_str_to_bytes(node0.validateaddress(dest_addr)['scriptPubKey'])
        verbose = True

        if mine:
            self.log.debug(f'compressmineoutputs: {self.node0_address1}, {inputs_cnt_per_tx}, {send_tx}, {100}, {verbose}')
            call_ret = node0.compressmineoutputs(self.node0_address1, inputs_cnt_per_tx, send_tx, 100, verbose)
            self.log.debug(f'compressmineoutputs result: {call_ret}')
            mask = 'get -- {} ( {:d} outputs )'
            parsed_stat = parse(mask, call_ret[1])
            self.log.debug(f'parsed_stat: {parsed_stat}')
            assert_equal(len(parsed_stat.fixed), 2)
            inputs_cnt_got = parsed_stat[1]
            total_amount_got = 0
            inputs_cnt_expected = inputs_cnt_normal + inputs_cnt_others + inputs_cnt_exist
            total_amount_expected = 0
        else:
            self.log.debug(f'compressoutputs: {self.node0_address1}, {dest_addr}, {inputs_cnt_per_tx}, {taxfree}, {send_tx}, {verbose}')
            call_ret = node0.compressoutputs(self.node0_address1, dest_addr, inputs_cnt_per_tx, taxfree, send_tx, verbose)
            self.log.debug(f'compressoutputs result: {call_ret}')
            transactions = call_ret[:-1]
            stat_obj = call_ret[-1]
            mask = "{{'flush': '{}', 'get': '{} ( {inputs_cnt_got:d} outputs, total amount {total_amount_got:d} )',{}"
            parsed_stat = parse(mask, str(stat_obj))
            self.log.debug(f'parsed_stat: {parsed_stat}')
            assert_equal(len(parsed_stat.named), 2)
            inputs_cnt_got = parsed_stat['inputs_cnt_got']
            total_amount_got = parsed_stat['total_amount_got']
            inputs_cnt_expected = inputs_cnt_normal + inputs_cnt_exist
            total_amount_expected = sum(sorted(self.amounts)) + ToSatoshi(amount_exist)

        assert_equal(inputs_cnt_got, inputs_cnt_expected)
        assert_equal(total_amount_got, ToSatoshi(total_amount_expected))
        inputs_cnt_got_in_tx = 0

        for got_hex in transactions:
            assert is_hex_str(got_hex), f'not hex str: {got_hex}'
            is_txid = (len(got_hex) == 64)
            assert_equal(send_tx, is_txid)
            tx_hex = node0.getrawtransaction(got_hex) if is_txid else got_hex
            tx = FromHex(CTransaction(), tx_hex)
            for input in tx.vin:
                if not input.prevout.hash:
                    # zero (taxfree) input - skip it
                    continue
                txid_hex = '%064x' % (input.prevout.hash)
                assert_in((txid_hex, input.prevout.n), utxo_set)
                utxo_set.remove((txid_hex, input.prevout.n))
                inputs_cnt_got_in_tx += 1
            assert_equal(len(tx.vout), outputs_cnt_expected)
            expected_dests = set([dest_script])
            if outputs_cnt_expected == 3:
                expected_dests.add(GraveScript1())
                expected_dests.add(GraveScript2())
            for output in tx.vout:
                assert_in(output.scriptPubKey, expected_dests)
                expected_dests.remove(output.scriptPubKey)
            assert_greater_than_or_equal(inputs_cnt_per_tx + bool(taxfree), len(tx.vin))
            assert_equal(expected_dests, set())

        assert_equal(inputs_cnt_got_in_tx, inputs_cnt_expected)

        if send_tx:
            for txid in transactions:
                verify_tx_sent(node0, txid)
            while len(node0.getrawmempool()) > 0:
                node0.generatetoaddress(1, self.miner_address)
            self.sync_all()
        return transactions if send_tx else []


    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        self.taxfree_cert_filename = os.path.join(self.options.tmpdir + '/node0/regtest', 'taxfree.cert')
        self.miner_address = node1.getnewaddress()
        node1.generate(25)  # to avoid appearing of mature coinbase node0's utxos
        self.sync_all()
        dest_addr = node1.getnewaddress()
        taxfrees = [None, True] if self.options.withcert else [None, False]

        if self.options.withcert:
            (root_cert_hash, pass_cert_hash, super_key) = generate_certs_pair(node1, self.test_node, fee=fee,
                                                                              pass_cert_flag_default=SUPER_TX)
            node1.generate(1)
            self.sync_all()
            restart_node_with_cert(self, True, super_key.get_pubkey(), root_cert_hash, pass_cert_hash)
            node0.importprivkey(SecretBytesToBase58(super_key.get_secret()))
            node0.generatetoaddress(1, self.miner_address)

        for mine in [False, True]:
            for inputs_cnt_others in [0, 100]:
                for (inputs_cnt_per_tx, inputs_cnt_normal) in [(30, 300)]:
                    for taxfree in taxfrees:
                        for send_tx in [False, True]:
                            if not send_tx:
                                self.prepare_empty_node0()
                            self.check_compressoutputs(dest_addr, inputs_cnt_per_tx=inputs_cnt_per_tx, taxfree=taxfree,
                                                       send_tx=send_tx, mine=mine, inputs_cnt_normal=inputs_cnt_normal,
                                                       inputs_cnt_others=inputs_cnt_others, keep_utxos=send_tx)

        for mine in [False, True]:
            for (inputs_cnt_per_tx, inputs_cnt_normal) in [(1000, 20000)]:
                for send_tx in [False, True]:
                    if not send_tx:
                        self.prepare_empty_node0()
                    self.check_compressoutputs(dest_addr, inputs_cnt_per_tx=inputs_cnt_per_tx, taxfree=None,
                                               send_tx=send_tx, mine=mine, inputs_cnt_normal=inputs_cnt_normal,
                                               inputs_cnt_others=0, keep_utxos=send_tx)

        height1 = node0.getblockcount()
        address1 = node0.getnewaddress()
        address2 = node0.getnewaddress()
        address3 = node0.getnewaddress()
        blocks1 = node0.generatetoaddress(20, address1)
        blocks2 = node0.generatetoaddress(20, address2)
        blocks3 = node0.generatetoaddress(20, address3)
        self.log.debug(f'addresses: {address1}, {address2}, {address3}')
        self.sync_all()

        # Here coinbase inputs are immature and must not be processed:
        # Check coinbase inputs alone and together with normal ones:
        for mine in [False, True]:
            for (inputs_cnt_per_tx, inputs_cnt_normal) in [(12, 0), (45, 50)]:
                for send_tx in [False, True]:
                    if not send_tx:
                        self.prepare_empty_node0()
                    self.check_compressoutputs(dest_addr, inputs_cnt_per_tx=inputs_cnt_per_tx, taxfree=None,
                                               send_tx=send_tx, mine=mine, inputs_cnt_normal=inputs_cnt_normal,
                                               inputs_cnt_others=0, address=address1, keep_utxos=send_tx)

        self.prepare_empty_node0()
        height2 = node0.getblockcount()
        node0.generatetoaddress(160 - (height2 - height1), self.miner_address)
        self.sync_all()
        inputs_cnt_per_tx = 15
        inputs_cnt_normal = 0

        # Here all coinbase inputs (address1, address2, address3) are mature,
        # mine = False, only coinbase inputs for address1 must be processed:
        for send_tx in [False, True]:
            compr_txids = self.check_compressoutputs(dest_addr, inputs_cnt_per_tx=inputs_cnt_per_tx, taxfree=None,
                                                     send_tx=send_tx, mine=False, inputs_cnt_normal=inputs_cnt_normal,
                                                     inputs_cnt_others=0, inputs_cnt_exist=20,
                                                     amount_exist=CB_AMOUNT_AFTER_BLOCK_100 * 20,
                                                     utxos_exist=utxos_from_blocks(node0, blocks1),
                                                     address=address1, keep_utxos=send_tx)

        compr_utxos = [(t, 0) for t in compr_txids]
        spend_inputs(node0, compr_utxos, node0.getbalance() - CB_AMOUNT_AFTER_BLOCK_100 * 40)

        # mine = True, coinbase inputs for (address2 and address3) must be processed:
        for send_tx in [False, True]:
            self.check_compressoutputs(dest_addr, inputs_cnt_per_tx=inputs_cnt_per_tx, taxfree=None, send_tx=send_tx,
                                       mine=True, inputs_cnt_normal=inputs_cnt_normal, inputs_cnt_others=0,
                                       inputs_cnt_exist=40, amount_exist=CB_AMOUNT_AFTER_BLOCK_100 * 40,
                                       utxos_exist=utxos_from_blocks(node0, blocks2 + blocks3),
                                       address=address2, keep_utxos=send_tx)


if __name__ == '__main__':
    CompressOutputsTest().main()
