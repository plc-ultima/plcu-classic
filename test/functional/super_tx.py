#!/usr/bin/env python3
# Copyright (c) 2021 The PLC Ultima Classic Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

# node0: normal super-tx with certificate; super-tx with certificate with parameter -smart-createrawtransaction
# Check balance before/after with node0
# Generate blocks by node1 or to node1 address
# self.test_node uses node1
# Generate certs and make 2p2 checks with node1

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.certs import *
from test_framework.blocktools import create_coinbase, create_block

'''
super_tx.py
'''

fee = Decimal('0.00001000')
maxfee = Decimal('0.00200000')
BAD_CERTIFICATE = 'mandatory-script-verify-flag-failed (Bad plc certificate)'
BAD_BURNED = 'bad-burned'


def compose_super_tx(input_utxos, input_key, utxo_cert_root, utxo_cert_ca3, user_super_key, dest_pkhs_and_amounts):
    tx3 = CTransaction()

    for input_utxo in input_utxos:
        tx3.vin.append(CTxIn(input_utxo, GetP2PKHScript(hash160(input_key.get_pubkey())), 0xffffffff))
    tx3.vin.append(CTxIn(COutPoint(0,0), GetP2SHMoneyboxScript(OP_CHECKSUPER), 0xffffffff))

    # append dest_outputs to tx:
    for dest_pkh in dest_pkhs_and_amounts:
        amount = dest_pkhs_and_amounts[dest_pkh]
        tx3.vout.append(CTxOut(ToSatoshi(amount), GetP2PKHScript(dest_pkh)))

    for i in range(len(input_utxos)):
        (sig_hash, err) = SignatureHash(CScript(tx3.vin[i].scriptSig), tx3, i, SIGHASH_ALL)
        assert (err is None)
        signature = input_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx3.vin[i].scriptSig = CScript([signature, input_key.get_pubkey()])

    for i in range(len(input_utxos), len(tx3.vin)):
        # There are no common rules of composing signature for p2sh transaction inputs,
        # we made agreement to replace scriptSig with inner script (CScript(OP_CHECKREWARD)), not
        # with the public key script of the referenced transaction output
        # (excluding all occurences of OP CODESEPARATOR in it), as for p2pkh transactions:
        scriptSig = CScript([OP_CHECKSUPER])
        (sig_hash, err) = SignatureHash(scriptSig, tx3, i, SIGHASH_ALL)
        assert (err is None)
        signatures_and_keys = []
        signature = user_super_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        signatures_and_keys.append(signature)
        signatures_and_keys.append(user_super_key.get_pubkey())
        tx3.vin[i].scriptSig = CScript(signatures_and_keys +
                                       [ ser_uint256(utxo_cert_root.hash), utxo_cert_root.n,
                                         ser_uint256(utxo_cert_ca3.hash), utxo_cert_ca3.n,
                                         CScript([OP_CHECKSUPER])])
    tx3.rehash()
    return tx3


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

class SuperTxTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [['-debug', '-whitelist=127.0.0.1']] * self.num_nodes
        self.taxfree_cert_filename = None
        self.default_amount = Decimal('7.55')
        self.default_outpoints = []
        self.default_user_key = None
        self.miner_address = None
        self.inputs_for_node0 = {}
        self.certs = {}

    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(1), self.nodes[1], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()

    def create_inputs_for_address(self, address, amount, node_from, mine_block=False):
        txid = node_from.sendtoaddress(address, amount)
        verify_tx_sent(node_from, txid)
        if mine_block:
            node_from.generatetoaddress(1, self.miner_address)
        n = find_output(node_from, txid, amount)
        inputs = [{'txid': txid, 'vout': n}]
        return (inputs, address)

    def lock_inputs(self, node, inputs_for_node):
        for amount in inputs_for_node.keys():
            for input_and_addr in inputs_for_node[amount]:
                input = input_and_addr[0]
                node.lockunspent(False, input)

    def get_zero_inputs_count(self, tx_hex):
        tx = FromHex(CTransaction(), tx_hex)
        zero_inputs = [inp.prevout.hash for inp in tx.vin if (not inp.prevout.hash and not inp.prevout.n)]
        return len(zero_inputs)


    def check_scen_001(self, node0, inputs_for_node, amount, super_key=None, certs=[], mine_block=True,
                       manual_add_taxfree_input=True, taxfree_input_must_exist=True, accepted=True, reject_reason=None):
        (inputs, address) = inputs_for_node[amount].pop(0)
        self.log.debug(f'inputs: {inputs}, address: {address}, amount: {amount}, left: {len(inputs_for_node[amount])}')
        node0.lockunspent(True, inputs)
        balance_before = node0.getbalance('', 0)
        dest_key = create_key()
        if manual_add_taxfree_input:
            null_input = {'txid': '00' * 32, 'vout': 0}
            inputs.append(null_input)
        raw_super = node0.createrawtransaction(inputs, {AddressFromPubkey(dest_key.get_pubkey()): amount - fee})
        zero_inputs_count = self.get_zero_inputs_count(raw_super)
        assert_equal(zero_inputs_count == 1, taxfree_input_must_exist)
        assert_equal(zero_inputs_count == 0, not taxfree_input_must_exist)
        sig_res = None
        try:
            if super_key:
                sig_res = node0.signrawtransaction(raw_super, [],
                                                   [SecretBytesToBase58(super_key.get_secret()), node0.dumpprivkey(address)],
                                                   'ALL', certs, [bytes_to_hex_str(super_key.get_pubkey())])
            else:
                sig_res = node0.signrawtransaction(raw_super)
        except JSONRPCException as e:
            self.log.debug(f'signrawtransaction JSONRPCException: {e}')

        self.log.debug(f'check_scen_001, amount: {amount}, super_key: {super_key}, mine_block: {mine_block}, '
                       f'sig_res: {sig_res}')

        # if tx is composed without zero (taxfree) input, sign operation will be ok, tx will fail later
        sig_res_always_ok = not taxfree_input_must_exist
        if not sig_res_always_ok:
            assert_equal(sig_res is not None and sig_res['complete'], accepted)
        if accepted:
            assert('errors' not in sig_res or len(sig_res['errors']) == 0)
            txid_super = node0.sendrawtransaction(sig_res['hex'])
            assert_in(txid_super, node0.getrawmempool())
            balance_after = node0.getbalance('', 0)
            assert_equal(balance_before, balance_after + amount)
            if mine_block:
                node0.generatetoaddress(1, self.miner_address)
        else:
            if not sig_res_always_ok and sig_res:
                assert_greater_than(len(sig_res['errors']), 0)
            if sig_res:
                assert_raises_rpc_error(None, reject_reason, node0.sendrawtransaction, sig_res['hex'])
            balance_after = node0.getbalance('', 0)
            assert_equal(balance_before, balance_after)


    def check_scen_002(self, amount):
        name = 'check_scen_002'
        self.log.debug(f'Entering {name}, amount: {amount} ...')
        show_time(name)
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        for node in self.nodes:
            assert_not_in('taxfree_certificate', node.getwalletinfo())

        self.sync_all()
        (root_cert_hash, pass_cert_hash, super_key) = generate_certs_pair(node1, self.test_node, fee=fee,
                                                                          pass_cert_flag_default=SUPER_TX)
        node1.generate(1)
        self.sync_all()

        dest_key = create_key()
        (inputs, _) = self.inputs_for_node0[amount].pop(0)
        null_input = {'txid': '00' * 32, 'vout': 0}
        inputs_with_taxfree = inputs + [null_input]
        outputs = {AddressFromPubkey(dest_key.get_pubkey()): amount - fee}

        # 1. Without cert, without smart-createrawtransaction param: no new tax-free inputs:
        raw_tx = node0.createrawtransaction(inputs, outputs)
        assert_equal(self.get_zero_inputs_count(raw_tx), 0)
        raw_tx = node0.createrawtransaction(inputs_with_taxfree, outputs)
        assert_equal(self.get_zero_inputs_count(raw_tx), 1)

        # 2. Without cert, with smart-createrawtransaction param: no new tax-free inputs:
        restart_node_with_cert(self, False, more_args=['-smart-createrawtransaction'])
        self.lock_inputs(node0, self.inputs_for_node0)
        raw_tx = node0.createrawtransaction(inputs, outputs)
        assert_equal(self.get_zero_inputs_count(raw_tx), 0)
        raw_tx = node0.createrawtransaction(inputs_with_taxfree, outputs)
        assert_equal(self.get_zero_inputs_count(raw_tx), 1)

        # 3. With cert, without smart-createrawtransaction param: no new tax-free inputs:
        restart_node_with_cert(self, True, super_key.get_pubkey(), root_cert_hash, pass_cert_hash)
        self.lock_inputs(node0, self.inputs_for_node0)
        raw_tx = node0.createrawtransaction(inputs, outputs)
        assert_equal(self.get_zero_inputs_count(raw_tx), 0)
        raw_tx = node0.createrawtransaction(inputs_with_taxfree, outputs)
        assert_equal(self.get_zero_inputs_count(raw_tx), 1)

        # 4. With cert, with smart-createrawtransaction param: 1 new tax-free input:
        restart_node_with_cert(self, True, super_key.get_pubkey(), root_cert_hash, pass_cert_hash,
                               more_args=['-smart-createrawtransaction'])
        self.lock_inputs(node0, self.inputs_for_node0)
        raw_tx = node0.createrawtransaction(inputs, outputs)
        assert_equal(self.get_zero_inputs_count(raw_tx), 1)
        raw_tx = node0.createrawtransaction(inputs_with_taxfree, outputs)
        assert_equal(self.get_zero_inputs_count(raw_tx), 2)

        # Return node0 to state without cert:
        restart_node_with_cert(self, False)
        self.lock_inputs(node0, self.inputs_for_node0)
        self.log.debug(f'Finish {name} ({show_time(name)} s)')


    def check_sendtoaddress(self, address, amount, subtractfeefromamount=False, mine_block=True, valid_cert=True):
        node0 = self.nodes[0]
        balance_before = node0.getbalance('', 0)
        self.log.debug(f'check sendtoaddress: node: 0, balance: {balance_before}, address: {address}, '
                       f'amount: {amount}, subtractfeefromamount: {subtractfeefromamount}, valid_cert: {valid_cert}, '
                       f'height: {node0.getblockcount()}')
        txid = node0.sendtoaddress(address, amount, '', '', subtractfeefromamount)
        verify_tx_sent(node0, txid)
        txraw = node0.getrawtransaction(txid, 1)
        balance_after = node0.getbalance('', 0)
        self.log.debug(f'txraw: {txraw}, balance_after: {balance_after}')
        outputs_cnt = len(txraw['vout'])
        burn_outputs = 0 if valid_cert else 2
        assert_greater_than_or_equal(outputs_cnt, 1 + burn_outputs)  # dest (if no change)
        assert_greater_than_or_equal(2 + burn_outputs, outputs_cnt)  # dest + change
        amount_sent_index = find_output_by_address(node0, address, tx_raw=txraw)
        amount_sent = txraw['vout'][amount_sent_index]['value']
        if valid_cert:
            assert_raises(RuntimeError, find_output_by_address, node0, GRAVE_ADDRESS_1, tx_raw=txraw)
            assert_raises(RuntimeError, find_output_by_address, node0, GRAVE_ADDRESS_2, tx_raw=txraw)
            burn_got_sum = 0
            burn_indexes = []
        else:
            burn1_index = find_output_by_address(node0, GRAVE_ADDRESS_1, tx_raw=txraw)
            burn2_index = find_output_by_address(node0, GRAVE_ADDRESS_2, tx_raw=txraw)
            burn_got1 = txraw['vout'][burn1_index]['value']
            burn_got2 = txraw['vout'][burn2_index]['value']
            burn_got_sum = burn_got1 + burn_got2
            burn_indexes = [burn1_index, burn2_index]
        change_indexes = [e for e in list(range(outputs_cnt)) if e not in [amount_sent_index] + burn_indexes]
        assert_greater_than_or_equal(1, len(change_indexes))
        change_index = change_indexes[0] if len(change_indexes) else -1
        change = txraw['vout'][change_index]['value'] if change_index != -1 else 0
        fee = -node0.gettransaction(txid)['fee']
        assert_greater_than_or_equal(maxfee, fee)

        if subtractfeefromamount:
            assert_equal(amount, amount_sent + burn_got_sum + fee)
            assert_equal(balance_before, balance_after + amount)
        else:
            assert_equal(amount, amount_sent)
            assert_equal(balance_before, balance_after + amount + burn_got_sum + fee)
        if mine_block:
            node0.generatetoaddress(1, self.miner_address)
        return (txid, fee + burn_got_sum)


    def check_sendmany(self, addresses_and_amounts, subtractfeefrom=[], mine_block=True, valid_cert=True):
        node0 = self.nodes[0]
        amount_sum = 0
        for addr in addresses_and_amounts:
            amount_sum += addresses_and_amounts[addr]
        balance_before = node0.getbalance('', 0)
        self.log.debug(f'check sendmany: node: 0, balance: {balance_before}, amount_sum: {amount_sum}, '
                       f'addresses_and_amounts: {addresses_and_amounts}, subtractfeefrom: {subtractfeefrom}, '
                       f'valid_cert: {valid_cert}, height: {node0.getblockcount()}')
        txid = node0.sendmany('', addresses_and_amounts, 1, '', subtractfeefrom)
        verify_tx_sent(node0, txid)
        txraw = node0.getrawtransaction(txid, 1)
        balance_after = node0.getbalance('', 0)
        self.log.debug(f'txraw: {txraw}')
        outputs_cnt = len(txraw['vout'])
        burn_outputs = 0 if valid_cert else 2
        assert_greater_than_or_equal(outputs_cnt, len(addresses_and_amounts) + burn_outputs)  # dests (if no change)
        assert_greater_than_or_equal(len(addresses_and_amounts) + 1 + burn_outputs, outputs_cnt)  # dests + change
        amount_sent_indexes_map = {}
        amount_sent_indexes_arr = []
        amount_sent_sum = 0
        for addr in addresses_and_amounts:
            amount_sent_index = find_output_by_address(node0, addr, tx_raw=txraw)
            amount_sent_indexes_map[addr] = amount_sent_index
            amount_sent_indexes_arr.append(amount_sent_index)
            amount_sent_sum += txraw['vout'][amount_sent_index]['value']
        if valid_cert:
            assert_raises(RuntimeError, find_output_by_address, node0, GRAVE_ADDRESS_1, tx_raw=txraw)
            assert_raises(RuntimeError, find_output_by_address, node0, GRAVE_ADDRESS_2, tx_raw=txraw)
            burn_got_sum = 0
            burn_indexes = []
        else:
            burn1_index = find_output_by_address(node0, GRAVE_ADDRESS_1, tx_raw=txraw)
            burn2_index = find_output_by_address(node0, GRAVE_ADDRESS_2, tx_raw=txraw)
            burn_got1 = txraw['vout'][burn1_index]['value']
            burn_got2 = txraw['vout'][burn2_index]['value']
            burn_got_sum = burn_got1 + burn_got2
            burn_indexes = [burn1_index, burn2_index]
        change_indexes = [e for e in list(range(outputs_cnt)) if e not in amount_sent_indexes_arr + burn_indexes]
        assert_greater_than_or_equal(1, len(change_indexes))
        change_index = change_indexes[0] if len(change_indexes) else -1
        change = txraw['vout'][change_index]['value'] if change_index != -1 else 0
        fee = -node0.gettransaction(txid)['fee']

        if len(subtractfeefrom) > 0:
            assert_equal(amount_sum, amount_sent_sum + burn_got_sum + fee)
            taxes = []
            for addr in addresses_and_amounts:
                amount_sent_index = amount_sent_indexes_map[addr]
                if addr in subtractfeefrom:
                    assert_greater_than(addresses_and_amounts[addr], txraw['vout'][amount_sent_index]['value'])
                    tax = addresses_and_amounts[addr] - txraw['vout'][amount_sent_index]['value']
                    taxes.append(tax)
                else:
                    assert_equal(addresses_and_amounts[addr], txraw['vout'][amount_sent_index]['value'])
            # Node calculates taxes with accuracy 2 satoshi, let it be so
            assert_greater_than_or_equal(2, ToSatoshi(max(taxes) - min(taxes)))
            assert_equal(balance_before, balance_after + amount_sum)
        else:
            for addr in addresses_and_amounts:
                amount_sent_index = amount_sent_indexes_map[addr]
                assert_equal(addresses_and_amounts[addr], txraw['vout'][amount_sent_index]['value'])
            assert_equal(amount_sum, amount_sent_sum)
            assert_equal(balance_before, balance_after + amount_sum + burn_got_sum + fee)
        if mine_block:
            node0.generatetoaddress(1, self.miner_address)
        return (txid, fee + burn_got_sum)


    def run_scenario(self, name, node, root_cert_key=None, root_cert_flags=None, root_cert_hash=None,
                     root_cert_sig_hash=None, root_cert_sig_key=None, root_cert_signature=None,
                     root_cert_revoked=False, pass_cert_key=None, pass_cert_flags=None, pass_cert_hash=None,
                     pass_cert_sig_hash=None, pass_cert_sig_key=None, pass_cert_signature=None,
                     pass_cert_revoked=False, super_key=None, keep_super_key=None, amount=None, accepted=True,
                     reject_reason_rpc=None, reject_reason_p2p=None, gen_certs=False, check_p2p=False,
                     check_rpc_manual=False, check_rpc_manual_smart=False, check_rpc_auto=False):
        amount = amount if amount is not None else self.default_amount
        show_time(name)
        self.log.info(f'Start scenario {name}, gen_certs: {gen_certs}, check_p2p: {check_p2p}, '
                      f'check_rpc_manual: {check_rpc_manual}, check_rpc_manual_smart: {check_rpc_manual_smart}, '
                      f'check_rpc_auto: {check_rpc_auto} ...')
        assert_equal(gen_certs or check_p2p or check_rpc_manual or check_rpc_manual_smart or check_rpc_auto, True)
        mine_blocks = [False, True]

        for no in self.nodes:
            assert_not_in('taxfree_certificate', no.getwalletinfo())

        if gen_certs:
            self.certs[name] = []
            for _ in range(3):
                certs_pair = generate_certs_pair(node, self.test_node, root_cert_key=root_cert_key,
                                                 root_cert_flags=root_cert_flags, root_cert_hash=root_cert_hash,
                                                 root_cert_sig_hash=root_cert_sig_hash,
                                                 root_cert_sig_key=root_cert_sig_key,
                                                 root_cert_signature=root_cert_signature,
                                                 root_cert_revoked=root_cert_revoked, pass_cert_key=pass_cert_key,
                                                 pass_cert_flags=pass_cert_flags, pass_cert_hash=pass_cert_hash,
                                                 pass_cert_sig_hash=pass_cert_sig_hash,
                                                 pass_cert_sig_key=pass_cert_sig_key,
                                                 pass_cert_signature=pass_cert_signature,
                                                 pass_cert_revoked=pass_cert_revoked, super_key=super_key,
                                                 keep_super_key=keep_super_key, fee=fee,
                                                 pass_cert_flag_default=SUPER_TX)
                self.certs[name].append(certs_pair)
            node.generatetoaddress(1, self.miner_address)

        # Check p2p first:
        if check_p2p:
            (root_cert_hash, pass_cert_hash, super_key) = self.certs[name].pop(0)
            dest_pkh = hash160(b'xepppp-001')
            if amount != self.default_amount:
                user_key = create_key()
                (outpoints, _) = generate_outpoints(node, 1, amount, AddressFromPubkey(user_key.get_pubkey()))
                node.generatetoaddress(1, self.miner_address)
            else:
                user_key = self.default_user_key
                outpoints = self.default_outpoints

            tx3 = compose_super_tx([outpoints.pop()], user_key, COutPoint(int(root_cert_hash, 16), 0),
                                   COutPoint(int(pass_cert_hash, 16), 0), super_key, {dest_pkh: amount - fee})
            send_tx(node, self.test_node, tx3, accepted, reject_reason_p2p)

        if check_rpc_manual or check_rpc_manual_smart:
            more_args = ['-smart-createrawtransaction'] if check_rpc_manual_smart else []
            (root_cert_hash, pass_cert_hash, super_key) = self.certs[name].pop(0)
            inputs_for_node = []
            inputs = []
            for _ in range(4):
                (input, address) = self.create_inputs_for_address(node.getnewaddress(), amount, node)
                node.lockunspent(False, input)
                inputs_for_node.append((input, address))
                inputs.extend(input)
            node.lockunspent(True, inputs)

            assert_equal(node, self.nodes[0])  # restart_node_with_cert is for node0
            restart_node_with_cert(self, True, super_key.get_pubkey(), root_cert_hash, pass_cert_hash, accepted,
                                   gen_block=False, more_args=more_args)
            self.lock_inputs(node, self.inputs_for_node0)
            node.generatetoaddress(1, self.miner_address)

            # createrawtransaction --> signrawtransaction(super_key) --> sendrawtransaction
            # with and without mining transactions into blocks
            certs = [
                {'txid': root_cert_hash, 'vout': 0},
                {'txid': pass_cert_hash, 'vout': 0},
            ]
            for mine_block in mine_blocks:
                if check_rpc_manual:
                    self.check_scen_001(node, self.inputs_for_node0, amount, super_key, certs, mine_block, True, True,
                                        accepted, reject_reason_rpc)
                else:
                    self.check_scen_001(node, self.inputs_for_node0, amount, super_key, certs, mine_block, False, accepted,
                                        accepted, reject_reason_rpc)

            node.importprivkey(SecretBytesToBase58(super_key.get_secret()))

            # createrawtransaction --> signrawtransaction(empty_keys_array) --> sendrawtransaction
            # with and without mining transactions into blocks
            for mine_block in mine_blocks:
                if check_rpc_manual:
                    self.check_scen_001(node, self.inputs_for_node0, amount, None, [], mine_block, True, True,
                                        accepted, reject_reason_rpc)
                else:
                    self.check_scen_001(node, self.inputs_for_node0, amount, None, [], mine_block, False, accepted,
                                        accepted, reject_reason_rpc)

            if check_rpc_auto:
                pkh1 = hash160(b'antonio-1')
                pkh2 = hash160(b'antonio-2')
                addr1 = AddressFromPubkeyHash(pkh1)
                addr2 = AddressFromPubkeyHash(pkh2)
                balance_before = node.getbalance()
                spent_sum = 0
                txids = []

                for mine_block in mine_blocks:
                    for subtractfeefromamount in [False, True]:
                        (txid, fee_this) = self.check_sendtoaddress(addr1, amount, subtractfeefromamount, mine_block, accepted)
                        txids.append(txid)
                        spent_this = amount if subtractfeefromamount else (amount + fee_this)
                        spent_sum += spent_this

                balance_after = node.getbalance()
                self.log.debug(f'balance_before: {balance_before}, balance_after: {balance_after}, spent_sum: {spent_sum}')
                for txid in txids:
                    assert_greater_than(node.getrawtransaction(txid, 1)['confirmations'], 0)
                assert_equal(balance_before, balance_after + spent_sum)

                balance_before = node.getbalance()
                spent_sum = 0
                txids = []

                for mine_block in mine_blocks:
                    for subtractfeefrom in [[], [addr1], [addr1, addr2]]:
                        (txid, fee_this) = self.check_sendmany({addr1: amount, addr2: amount * 3}, subtractfeefrom, mine_block,
                                                               accepted)
                        txids.append(txid)
                        spent_this = (amount * 4) if len(subtractfeefrom) else (amount * 4 + fee_this)
                        spent_sum += spent_this

                balance_after = node.getbalance()
                self.log.debug(f'balance_before: {balance_before}, balance_after: {balance_after}, spent_sum: {spent_sum}')
                for txid in txids:
                    assert_greater_than(node.getrawtransaction(txid, 1)['confirmations'], 0)
                assert_equal(balance_before, balance_after + spent_sum)

            restart_node_with_cert(self, False, gen_block=False)
            self.lock_inputs(node, self.inputs_for_node0)
            node.generatetoaddress(1, self.miner_address)

        self.log.debug(f'Finish scenario {name} ({show_time(name)} s)')


    def run_scenario_reload_cert_after_sync(self, amount=None, keep_super_key=None, accepted=True,
                                            reject_reason_rpc=None, check_p2p=False, check_rpc=False):
        name = 'reload_cert_after_sync'
        self.log.info(f'Start scenario {name}, check_p2p: {check_p2p}, check_rpc: {check_rpc} ...')
        show_time(name)
        assert_equal(check_p2p or check_rpc, True)
        amount = amount if amount is not None else self.default_amount
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        for no in self.nodes:
            assert_not_in('taxfree_certificate', no.getwalletinfo())

        if check_p2p:
            self.sync_all()
            disconnect_nodes(self.nodes[0], 1)
            disconnect_nodes(self.nodes[1], 0)
            (root_cert_hash, pass_cert_hash, super_key) = generate_certs_pair(node1, self.test_node, fee=fee,
                                                                              pass_cert_flag_default=SUPER_TX,
                                                                              keep_super_key=keep_super_key)
            node1.generate(1)

            restart_node_with_cert(self, True, super_key.get_pubkey(), root_cert_hash, pass_cert_hash, accepted=False,
                                   gen_block=False, nodes_to_sync=self.nodes[:1])
            self.lock_inputs(node0, self.inputs_for_node0)
            # node0 doesn't have blocks with cert and its inputs, here cert is invalid:
            assert_not_in('taxfree_certificate', node0.getwalletinfo())

            connect_nodes_bi(self.nodes, 0, 1)
            self.sync_all()

            # after join network, cert is valid, but node will reload it only on try to use it, not here
            assert_not_in('taxfree_certificate', node0.getwalletinfo())

            # createrawtransaction --> signrawtransaction(super_key) --> sendrawtransaction
            certs = [{'txid': root_cert_hash, 'vout': 0}, {'txid': pass_cert_hash, 'vout': 0}]
            self.check_scen_001(node0, self.inputs_for_node0, amount, super_key, certs, True, accepted=accepted,
                                reject_reason=reject_reason_rpc)

            self.log.debug(f'Will importprivkey...')
            node0.importprivkey(SecretBytesToBase58(super_key.get_secret()))

            # createrawtransaction --> signrawtransaction(empty_keys_array) --> sendrawtransaction
            self.check_scen_001(node0, self.inputs_for_node0, amount, None, [], True, accepted=accepted,
                                reject_reason=reject_reason_rpc)

            assert_equal(len(node0.getrawmempool()), 0)
            restart_node_with_cert(self, False, accepted=False, gen_block=False)
            self.lock_inputs(node0, self.inputs_for_node0)
            node0.generatetoaddress(1, self.miner_address)

        if check_rpc:
            self.sync_all()
            disconnect_nodes(self.nodes[0], 1)
            disconnect_nodes(self.nodes[1], 0)

            (root_cert_hash, pass_cert_hash, super_key) = generate_certs_pair(node1, self.test_node, fee=fee,
                                                                              pass_cert_flag_default=SUPER_TX,
                                                                              keep_super_key=keep_super_key)
            node1.generate(1)

            restart_node_with_cert(self, True, super_key.get_pubkey(), root_cert_hash, pass_cert_hash, accepted=False,
                                   gen_block=False, next_indexes=[], nodes_to_sync=self.nodes[:1],
                                   more_args=['-smart-createrawtransaction'])
            self.lock_inputs(node0, self.inputs_for_node0)
            # node0 doesn't have blocks with cert and its inputs, here cert is invalid:
            assert_not_in('taxfree_certificate', node0.getwalletinfo())

            # here cert is invalid - sendtoaddress must be with burn: # TTT what???
            txid1 = node0.sendtoaddress(node0.getnewaddress(), amount)
            tx1 = node0.gettransaction(txid1)
            find_burned_amount_in_tx(tx1, True)

            # join nodes:
            connect_nodes_bi(self.nodes, 0, 1)
            sync_blocks(self.nodes)
            node0.generatetoaddress(1, self.miner_address)
            self.sync_all()
            # after join network, cert is valid, but node will reload it only on try to use it, not here
            assert_not_in('taxfree_certificate', node0.getwalletinfo())

            # here cert is valid, but before importprivkey call node has no superkey - sendtoaddress will fail:
            assert_raises_rpc_error(None, 'Signing super failed', node0.sendtoaddress, node1.getnewaddress(), amount)

            self.log.debug(f'Will importprivkey...')
            node0.importprivkey(SecretBytesToBase58(super_key.get_secret()))

            # here sendtoaddress must be without burn:
            txid2 = node0.sendtoaddress(node0.getnewaddress(), amount)
            tx2 = node0.gettransaction(txid2)
            find_burned_amount_in_tx(tx2, False)
            node0.generatetoaddress(1, self.miner_address)
            restart_node_with_cert(self, False, accepted=False, gen_block=False)
            self.lock_inputs(node0, self.inputs_for_node0)

        self.log.debug(f'Finish scenario {name} ({show_time(name)} s)')


    def run_test(self):
        self.taxfree_cert_filename = os.path.join(self.options.tmpdir + '/node0/regtest', 'taxfree.cert')
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        for amount in [Decimal('1.12345678'), Decimal('5.44'), Decimal(8)] * 8 + [self.default_amount] * 26 * 8:
            if amount not in self.inputs_for_node0:
                self.inputs_for_node0[amount] = []
            self.inputs_for_node0[amount].append(self.create_inputs_for_address(node0.getnewaddress(), amount, node1))

        self.log.debug(f'inputs_for_node0:')
        for a in self.inputs_for_node0.keys():
            inputs = self.inputs_for_node0[a]
            line = f'amount: {a}, inputs ({len(inputs)}):\n'
            for inp in inputs:
                line += f'\t{inp}\n'
            self.log.debug(line)

        self.miner_address = node1.getnewaddress()
        node1.generate(25) # is needed to remove influence of generate() calls to node0 balance
        self.sync_all()
        self.test_node.sync_with_ping()
        self.lock_inputs(node0, self.inputs_for_node0)

        # Transfer some amount node1 --> node0 and don't mine it into a block:
        for _ in range(20):
            txid = node1.sendtoaddress(node0.getnewaddress(), 1000)
            verify_tx_sent(node1, txid)
        self.sync_all()

        # ... and now mine it into a block:
        node1.generate(1)
        self.sync_all()

        self.default_user_key = create_key()
        (self.default_outpoints, _) = generate_outpoints(node0, 40, self.default_amount,
                                                         AddressFromPubkey(self.default_user_key.get_pubkey()))
        node0.generatetoaddress(1, self.miner_address)
        self.sync_all()

        self.run_scenario_reload_cert_after_sync(check_p2p=True)
        self.run_scenario_reload_cert_after_sync(check_rpc=True)
        self.check_scen_002(Decimal('5.44'))

        for (node, gen_certs, check_p2p, check_rpc_manual, check_rpc_manual_smart, check_rpc_auto) in [
            (node1, True, True, False, False, False), (node0, False, False, True, False, True),
            (node0, False, False, False, True, False)]:

            self.sync_all()

            super_key1 = create_key()
            super_key2 = create_key()
            super_key3 = create_key()
            fake_root_key = create_key()
            fake_pass_key = create_key()
            fake_super_key = create_key()

            self.run_scenario('base_positive_1', node, amount=Decimal(8), keep_super_key=super_key1,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto)

            self.run_scenario('base_positive_2', node, amount=Decimal('1.12345678'), keep_super_key=super_key1,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto)

            self.run_scenario('positive_supertx_flag_in_root_cert_v1', node,
                              root_cert_flags=SUPER_TX,
                              pass_cert_flags=0,
                              keep_super_key=super_key2,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto)

            self.run_scenario('positive_supertx_flag_in_root_cert_v2', node,
                              root_cert_flags=SUPER_TX,
                              pass_cert_flags=SILVER_HOOF | ALLOW_MINING,
                              keep_super_key=super_key2,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto)

            self.run_scenario('missing_root_cert', node,
                              root_cert_hash=bytes_to_hex_str(hash256(b'xyu')),
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('zero_root_cert', node,
                              root_cert_hash='00' * 32,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('missing_pass_cert', node,
                              pass_cert_hash=bytes_to_hex_str(hash256(b'xyu-again')),
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('zero_pass_cert', node,
                              pass_cert_hash='00' * 32,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('zero_both_certs', node,
                              root_cert_hash='00' * 32,
                              pass_cert_hash='00' * 32,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('tx_instead_of_root_cert', node,
                              root_cert_hash=txid,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('tx_instead_of_pass_cert', node,
                              pass_cert_hash=txid,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('root_cert_is_not_root', node,
                              root_cert_key=fake_root_key,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('pass_cert_is_not_child_of_root', node,
                              pass_cert_key=fake_pass_key,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('super_key_not_mentioned_in_cert', node,
                              super_key=fake_super_key,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('no_supertx_flag_in_cert_v1', node,
                              pass_cert_flags=0,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=[BAD_BURNED, BAD_CERTIFICATE])

            self.run_scenario('no_supertx_flag_in_cert_v2', node,
                              pass_cert_flags=SILVER_HOOF | ALLOW_MINING,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=[BAD_BURNED, BAD_CERTIFICATE])

            self.run_scenario('root_cert_revoked', node,
                              root_cert_revoked=True,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('pass_cert_revoked', node,
                              pass_cert_revoked=True,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('root_cert_empty_signature', node,
                              root_cert_signature=b'',
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('pass_cert_empty_signature', node,
                              pass_cert_signature=b'',
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('root_cert_invalid_sig_hash', node,
                              root_cert_sig_hash=hash256(b'no!'),
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('pass_cert_invalid_sig_hash', node,
                              pass_cert_sig_hash=hash256(b'no-no-no dont even think'),
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('root_cert_block_signed_with_another_key', node,
                              root_cert_sig_key=fake_root_key,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            self.run_scenario('pass_cert_block_signed_with_another_key', node,
                              pass_cert_sig_key=fake_pass_key,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            fake_signature = sign_compact(hash256(b'no_chance_either'), fake_root_key.get_secret())
            self.run_scenario('root_cert_invalid_signature', node,
                              root_cert_signature=fake_signature,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)

            fake_signature = sign_compact(hash256(b'aaaaaaaaaaaa'), fake_pass_key.get_secret())
            self.run_scenario('pass_cert_invalid_signature', node,
                              pass_cert_signature=fake_signature,
                              keep_super_key=super_key3,
                              gen_certs=gen_certs, check_p2p=check_p2p, check_rpc_manual=check_rpc_manual,
                              check_rpc_manual_smart=check_rpc_manual_smart, check_rpc_auto=check_rpc_auto,
                              accepted=False,
                              reject_reason_p2p=BAD_CERTIFICATE,
                              reject_reason_rpc=BAD_BURNED)


if __name__ == '__main__':
    SuperTxTest().main()
