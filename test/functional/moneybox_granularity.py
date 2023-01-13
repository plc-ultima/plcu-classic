#!/usr/bin/env python3
# Copyright (c) 2021 The PLC Ultima Classic Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.certs import *
from test_framework.blocktools import create_coinbase

'''
moneybox_granularity.py
'''

fee = Decimal('0.00001000')

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


class MoneyboxGranularityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-debug', '-whitelist=127.0.0.1', '-moregranularity-regtest=210:1000000000']] * self.num_nodes
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


    def run_scenario(self, name, node, mint_reward, moneybox_change, refill_moneybox_gran, moneybox_refill_amount,
                     needed_moneybox_utxos, refill_moneybox_accepted=True):
        height = node.getblockcount()
        self.log.debug(f'Run scenario {name}, height: {height}, mint_reward: {mint_reward}, '
                       f'moneybox_change: {moneybox_change}, refill_moneybox_gran: {refill_moneybox_gran}, '
                       f'moneybox_refill_amount: {moneybox_refill_amount}, '
                       f'needed_moneybox_utxos: {needed_moneybox_utxos}, '
                       f'refill_moneybox_accepted: {refill_moneybox_accepted} ...')

        now = node.getblockheader(node.getbestblockhash())['time']
        (tx3, _) = compose_mint_tx([self.outpoints.pop()], self.moneybox_utxos[0:needed_moneybox_utxos],
                                   COutPoint(int(self.root_cert_hash, 16), 0), COutPoint(int(self.pass_cert_hash, 16), 0),
                                   self.user_key, Decimal(4500), now + ONE_YEAR * 10, Decimal(mint_reward) - fee,
                                   moneybox_change, True)
        del self.moneybox_utxos[0:needed_moneybox_utxos]
        mint_txid = send_tx(node, self.test_node, tx3, True, verbose=True)
        self.log.debug(f'mint tx {mint_txid}: {print_tx_ex(tx3)}')

        # We compose a new block and refill money-box, and then ensure the node accepts this block:
        parent_hash = node.getbestblockhash()
        parent_block = node.getblock(parent_hash, 2)
        block = CBlock()
        block.nVersion = parent_block['version']
        block.hashPrevBlock = int(parent_hash, 16)
        block.nTime = parent_block['time'] + 1
        block.nBits = int(parent_block['bits'], 16)
        height = parent_block['height'] + 1
        coinbase = create_coinbase(height, None, 0, ToSatoshi(moneybox_refill_amount),
                                   granularity=ToSatoshi(refill_moneybox_gran))
        block.vtx.append(coinbase)
        mempool = node.getrawmempool()
        for txid in mempool:
            tx = FromHex(CTransaction(), node.getrawtransaction(txid))
            block.vtx.append(tx)
            self.log.debug(f'tx from mempool {txid}: added to block')
        block.hashMerkleRoot = block.calc_merkle_root()
        block.nNonce = random.randint(0, 0xffff)
        block.solve()
        self.test_node.send_and_ping(msg_block(block))
        self.log.debug(f'parent_hash: {parent_hash}, block.hash: {block.hash}, accepted: {refill_moneybox_accepted}')
        assert_equal(int(node.getbestblockhash(), 16) == block.sha256, refill_moneybox_accepted)
        if not refill_moneybox_accepted:
            node.generate(1)  # mine mint_tx into a block anyway
        self.log.debug(f'Finish scenario {name}')


    def run_test(self):
        node0 = self.nodes[0]
        (self.root_cert_hash, self.pass_cert_hash, red_key) = generate_certs_pair(node0, self.test_node, fee=fee,
                                                                                  pass_cert_flag_default=SILVER_HOOF)

        # User money:
        self.user_key = red_key
        (self.outpoints, _) = generate_outpoints(node0, 10, Decimal(4500), AddressFromPubkey(self.user_key.get_pubkey()))
        node0.generate(1)
        self.sync_all()
        self.test_node.sync_with_ping()

        block_hash = node0.getblockhash(1)
        (self.moneybox_utxos, _) = parse_moneybox_utxos(node0, block_hash)

        mint_reward = Decimal(101)
        moneybox_change = Decimal(95)
        moneybox_refill_amount = Decimal(105)
        needed_moneybox_utxos = 2

        for (refill_moneybox_gran, accepted) in [(Decimal(100), True), (Decimal(10), False)]:
            self.run_scenario('moneybox_gran_100', node0, mint_reward=mint_reward, moneybox_change=moneybox_change,
                              refill_moneybox_gran=refill_moneybox_gran, moneybox_refill_amount=moneybox_refill_amount,
                              needed_moneybox_utxos=needed_moneybox_utxos, refill_moneybox_accepted=accepted)

        node0.generate(12)
        # Here granularity is 10 coins due to parameter -moregranularity-regtest
        # mint tx still returns change (moneybox_change) 95 coins, that is more than new granularity,
        # but no more than old one, it is accepted anyway.
        # refill_moneybox_gran (granularity in coinbase tx) must be 10 coins

        for (refill_moneybox_gran, accepted) in [(Decimal(100), False), (Decimal(10), True)]:
            self.run_scenario('moneybox_gran_10', node0, mint_reward=mint_reward, moneybox_change=moneybox_change,
                              refill_moneybox_gran=refill_moneybox_gran, moneybox_refill_amount=moneybox_refill_amount,
                              needed_moneybox_utxos=needed_moneybox_utxos, refill_moneybox_accepted=accepted)


if __name__ == '__main__':
    MoneyboxGranularityTest().main()
