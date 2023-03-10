#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the fundrawtransaction RPC."""

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import *
from test_framework.script import *


def get_unspent(listunspent, amount):
    for utx in listunspent:
        if utx['amount'] == amount:
            return utx
    raise AssertionError('Could not find unspent with amount={}'.format(amount))

class RawTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.setup_nodes()

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 0, 3)

    def run_test(self):
        min_relay_tx_fee = self.nodes[0].getnetworkinfo()['relayfee']
        # This test is not meant to test fee estimation and we'd like
        # to be sure all txs are sent at a consistent desired feerate
        for node in self.nodes:
            node.settxfee(min_relay_tx_fee)

        # if the fee's positive delta is higher than this value tests will fail,
        # neg. delta always fail the tests.
        # The size of the signature of every input may be at most 2 bytes larger
        # than a minimum sized signature.

        #            = 2 bytes * minRelayTxFeePerByte
        feeTolerance = 2 * min_relay_tx_fee/1000

        self.nodes[0].generate(15)
        self.sync_all()
        self.nodes[2].generate(125)
        self.sync_all()

        # ensure that setting changePosition in fundraw with an exact match is handled properly
        amount = Decimal(50000)
        (burn1, burn2, rest) = BurnedAndChangeAmount(amount)
        assert_equal(burn1 + burn2 + rest, amount)
        rawmatch = self.nodes[2].createrawtransaction([], {self.nodes[2].getnewaddress(): rest})
        rawmatch = self.nodes[2].fundrawtransaction(rawmatch, {"changePosition": 1, "subtractFeeFromOutputs": [0]})
        # assert_equal(rawmatch["changepos"], -1) # impossible to verify because node adds burn outputs itself
        assert_greater_than(rawmatch['fee'], 0)

        watchonly_address = self.nodes[0].getnewaddress()
        watchonly_pubkey = self.nodes[0].validateaddress(watchonly_address)["pubkey"]
        watchonly_amount = Decimal(200)
        self.nodes[3].importpubkey(watchonly_pubkey, "", True)
        # watchonly_txid = self.nodes[0].sendtoaddress(watchonly_address, watchonly_amount)
        txid = self.nodes[0].sendtoaddress(self.nodes[3].getnewaddress(), watchonly_amount / 10)
        verify_tx_sent(self.nodes[0], txid)

        txid = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1.5)
        verify_tx_sent(self.nodes[0], txid)
        txid = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1.0)
        verify_tx_sent(self.nodes[0], txid)
        txid = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 5.0)
        verify_tx_sent(self.nodes[0], txid)

        self.nodes[0].generate(1)
        self.sync_all()

        ###############
        # simple test #
        ###############
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 1.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        assert_greater_than(fee, 0)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        assert(len(dec_tx['vin']) > 0) #test that we have enough inputs

        ##############################
        # simple test with two coins #
        ##############################
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 2.2 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        assert_greater_than(fee, 0)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        assert(len(dec_tx['vin']) > 0) #test if we have enough inputs

        ##############################
        # simple test with two coins #
        ##############################
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 2.6 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        assert_greater_than(fee, 0)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        assert(len(dec_tx['vin']) > 0)
        assert_equal(dec_tx['vin'][0]['scriptSig']['hex'], '')


        ################################
        # simple test with two outputs #
        ################################
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 2.6, self.nodes[1].getnewaddress() : 2.5 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        assert_greater_than(fee, 0)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        for out in dec_tx['vout']:
            totalOut += out['value']

        assert(len(dec_tx['vin']) > 0)
        assert_equal(dec_tx['vin'][0]['scriptSig']['hex'], '')


        #########################################################################
        # test a fundrawtransaction with a VIN greater than the required amount #
        #########################################################################
        utx = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']}]
        outputs = { self.nodes[0].getnewaddress() : 1.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        assert_greater_than(fee, 0)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        for out in dec_tx['vout']:
            totalOut += out['value']

        assert_equal(fee + totalOut, utx['amount']) #compare vin total and totalout+fee


        # This block of test is hardly possible to reproduce in version with burning, skip it
        #####################################################################
        # test a fundrawtransaction with which will not get a change output #
        #####################################################################
        # utx = get_unspent(self.nodes[2].listunspent(), 5)
        # inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']}]
        # outputs = { self.nodes[0].getnewaddress() : Decimal(5.0) - fee - feeTolerance }
        # rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        # dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        # assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])
        # rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        # fee = rawtxfund['fee']
        # dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        # totalOut = 0
        # for out in dec_tx['vout']:
        #     totalOut += out['value']
        # assert_equal(rawtxfund['changepos'], -1)
        # assert_equal(fee + totalOut, utx['amount']) #compare vin total and totalout+fee


        ####################################################
        # test a fundrawtransaction with an invalid option #
        ####################################################
        utx = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']} ]
        outputs = { self.nodes[0].getnewaddress() : Decimal(4.0) }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        assert_raises_rpc_error(-3, "Unexpected key foo", self.nodes[2].fundrawtransaction, rawtx, {'foo':'bar'})

        ############################################################
        # test a fundrawtransaction with an invalid change address #
        ############################################################
        utx = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']} ]
        outputs = { self.nodes[0].getnewaddress() : Decimal(4.0) }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])
        assert_raises_rpc_error(None, "changeAddress must be a valid plcultimac address", self.nodes[2].fundrawtransaction, rawtx, {'changeAddress':'foobar'})

        ############################################################
        # test a fundrawtransaction with a provided change address #
        ############################################################
        utx = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']} ]
        outputs = { self.nodes[0].getnewaddress() : Decimal(4.0) }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        change = self.nodes[2].getnewaddress()
        assert_raises_rpc_error(-8, "changePosition out of bounds", self.nodes[2].fundrawtransaction, rawtx, {'changeAddress':change, 'changePosition':2})
        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, {'changeAddress': change, 'changePosition': 0})
        assert_greater_than(rawtxfund['fee'], 0)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        out = dec_tx['vout'][0]
        assert_equal(change, out['scriptPubKey']['addresses'][0])


        #########################################################################
        # test a fundrawtransaction with a VIN smaller than the required amount #
        #########################################################################
        utx = get_unspent(self.nodes[2].listunspent(), 1)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']}]
        outputs = { self.nodes[0].getnewaddress() : 1.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)

        # 4-byte version + 1-byte vin count + 36-byte prevout then script_len
        rawtx = rawtx[:82] + "0100" + rawtx[84:]

        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])
        assert_equal("00", dec_tx['vin'][0]['scriptSig']['hex'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        assert_greater_than(fee, 0)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        matchingOuts = 0
        for i, out in enumerate(dec_tx['vout']):
            totalOut += out['value']
            if out['scriptPubKey']['addresses'][0] in outputs:
                matchingOuts+=1
            elif out['scriptPubKey']['addresses'][0] in [GRAVE_ADDRESS_1, GRAVE_ADDRESS_2]:
                pass
            else:
                assert_equal(i, rawtxfund['changepos'])

        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])
        assert_equal("00", dec_tx['vin'][0]['scriptSig']['hex'])

        assert_equal(matchingOuts, 1)
        burn_outputs_cnt = 2
        assert_equal(len(dec_tx['vout']), 2 + burn_outputs_cnt)


        ###########################################
        # test a fundrawtransaction with two VINs #
        ###########################################
        utx = get_unspent(self.nodes[2].listunspent(), 1)
        utx2 = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']},{'txid' : utx2['txid'], 'vout' : utx2['vout']} ]
        outputs = { self.nodes[0].getnewaddress() : 6.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        assert_greater_than(fee, 0)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        matchingOuts = 0
        for out in dec_tx['vout']:
            totalOut += out['value']
            if out['scriptPubKey']['addresses'][0] in outputs:
                matchingOuts+=1

        assert_equal(matchingOuts, 1)
        assert_equal(len(dec_tx['vout']), 2 + burn_outputs_cnt)

        matchingIns = 0
        for vinOut in dec_tx['vin']:
            for vinIn in inputs:
                if vinIn['txid'] == vinOut['txid']:
                    matchingIns+=1

        assert_equal(matchingIns, 2) #we now must see two vins identical to vins given as params

        #########################################################
        # test a fundrawtransaction with two VINs and two vOUTs #
        #########################################################
        utx = get_unspent(self.nodes[2].listunspent(), 1)
        utx2 = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']},{'txid' : utx2['txid'], 'vout' : utx2['vout']} ]
        outputs = { self.nodes[0].getnewaddress() : 6.0, self.nodes[0].getnewaddress() : 1.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        assert_greater_than(fee, 0)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        matchingOuts = 0
        for out in dec_tx['vout']:
            totalOut += out['value']
            if out['scriptPubKey']['addresses'][0] in outputs:
                matchingOuts+=1

        assert_equal(matchingOuts, 2)
        assert_equal(len(dec_tx['vout']), 3 + burn_outputs_cnt)

        ##############################################
        # test a fundrawtransaction with invalid vin #
        ##############################################
        listunspent = self.nodes[2].listunspent()
        inputs  = [ {'txid' : "1c7f966dab21119bac53213a2bc7532bff1fa844c124fd750a7d0b1332440bd1", 'vout' : 0} ] #invalid vin!
        outputs = { self.nodes[0].getnewaddress() : 1.0}
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        assert_raises_rpc_error(-4, "Insufficient funds", self.nodes[2].fundrawtransaction, rawtx)

        ############################################################
        #compare fee of a standard pubkeyhash transaction
        inputs = []
        outputs = {self.nodes[1].getnewaddress():1.1}
        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[0].fundrawtransaction(rawtx)
        assert_greater_than(fundedTx['fee'], 0)

        #create same transaction over sendtoaddress
        txId = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1.1)
        verify_tx_sent(self.nodes[0], txId)
        signedFee = self.nodes[0].getrawmempool(True)[txId]['fee']

        #compare fee
        feeDelta = Decimal(fundedTx['fee']) - Decimal(signedFee)
        # assert(feeDelta >= 0 and feeDelta <= feeTolerance)
        ############################################################

        ############################################################
        #compare fee of a standard pubkeyhash transaction with multiple outputs
        inputs = []
        outputs = {self.nodes[1].getnewaddress():1.1,self.nodes[1].getnewaddress():1.2,self.nodes[1].getnewaddress():0.1,self.nodes[1].getnewaddress():1.3,self.nodes[1].getnewaddress():0.2,self.nodes[1].getnewaddress():0.3}
        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[0].fundrawtransaction(rawtx)
        assert_greater_than(fundedTx['fee'], 0)
        #create same transaction over sendtoaddress
        txId = self.nodes[0].sendmany("", outputs)
        verify_tx_sent(self.nodes[0], txId)
        signedFee = self.nodes[0].getrawmempool(True)[txId]['fee']

        #compare fee
        feeDelta = Decimal(fundedTx['fee']) - Decimal(signedFee)
        # assert(feeDelta >= 0 and feeDelta <= feeTolerance)
        ############################################################


        ############################################################
        #compare fee of a 2of2 multisig p2sh transaction

        # create 2of2 addr
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[1].getnewaddress()

        addr1Obj = self.nodes[1].validateaddress(addr1)
        addr2Obj = self.nodes[1].validateaddress(addr2)

        mSigObj = self.nodes[1].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey']])

        inputs = []
        outputs = {mSigObj:1.1}
        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[0].fundrawtransaction(rawtx)
        assert_greater_than(fundedTx['fee'], 0)

        #create same transaction over sendtoaddress
        txId = self.nodes[0].sendtoaddress(mSigObj, 1.1)
        verify_tx_sent(self.nodes[0], txId)
        signedFee = self.nodes[0].getrawmempool(True)[txId]['fee']

        #compare fee
        feeDelta = Decimal(fundedTx['fee']) - Decimal(signedFee)
        # assert(feeDelta >= 0 and feeDelta <= feeTolerance)
        ############################################################


        ############################################################
        #compare fee of a standard pubkeyhash transaction

        # create 4of5 addr
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[1].getnewaddress()
        addr3 = self.nodes[1].getnewaddress()
        addr4 = self.nodes[1].getnewaddress()
        addr5 = self.nodes[1].getnewaddress()

        addr1Obj = self.nodes[1].validateaddress(addr1)
        addr2Obj = self.nodes[1].validateaddress(addr2)
        addr3Obj = self.nodes[1].validateaddress(addr3)
        addr4Obj = self.nodes[1].validateaddress(addr4)
        addr5Obj = self.nodes[1].validateaddress(addr5)

        mSigObj = self.nodes[1].addmultisigaddress(4, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey']])

        inputs = []
        outputs = {mSigObj:1.1}
        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[0].fundrawtransaction(rawtx)
        assert_greater_than(fundedTx['fee'], 0)

        #create same transaction over sendtoaddress
        txId = self.nodes[0].sendtoaddress(mSigObj, 1.1)
        verify_tx_sent(self.nodes[0], txId)
        signedFee = self.nodes[0].getrawmempool(True)[txId]['fee']

        #compare fee
        feeDelta = Decimal(fundedTx['fee']) - Decimal(signedFee)
        # assert(feeDelta >= 0 and feeDelta <= feeTolerance)
        ############################################################


        ############################################################
        # spend a 2of2 multisig transaction over fundraw

        # create 2of2 addr
        addr1 = self.nodes[2].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()

        addr1Obj = self.nodes[2].validateaddress(addr1)
        addr2Obj = self.nodes[2].validateaddress(addr2)

        mSigObj = self.nodes[2].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey']])


        # send 1.2 PLCUC to msig addr
        txId = self.nodes[0].sendtoaddress(mSigObj, 1.2)
        verify_tx_sent(self.nodes[0], txId)
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()

        oldBalance = self.nodes[1].getbalance()
        inputs = []
        outputs = {self.nodes[1].getnewaddress():1.1}
        rawtx = self.nodes[2].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[2].fundrawtransaction(rawtx)
        assert_greater_than(fundedTx['fee'], 0)

        signedTx = self.nodes[2].signrawtransaction(fundedTx['hex'])
        txId = self.nodes[2].sendrawtransaction(signedTx['hex'])
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()

        # make sure funds are received at node1
        assert_equal(oldBalance+Decimal('1.10000000'), self.nodes[1].getbalance())

        ############################################################
        # locked wallet test
        self.stop_node(0)
        self.nodes[1].node_encrypt_wallet("test")
        self.stop_node(2)
        self.stop_node(3)

        self.start_nodes()
        # This test is not meant to test fee estimation and we'd like
        # to be sure all txs are sent at a consistent desired feerate
        for node in self.nodes:
            node.settxfee(min_relay_tx_fee)

        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        connect_nodes_bi(self.nodes,0,3)
        self.sync_all()

        # drain the keypool
        self.nodes[1].getnewaddress()
        self.nodes[1].getrawchangeaddress()
        inputs = []
        outputs = {self.nodes[0].getnewaddress():1.1}
        rawtx = self.nodes[1].createrawtransaction(inputs, outputs)
        # fund a transaction that requires a new key for the change output
        # creating the key must be impossible because the wallet is locked

        # PLCUC fundrawtransaction returns change to input address, not to new one - no keepool needed
        # assert_raises_rpc_error(-4, "Keypool ran out, please call keypoolrefill first", self.nodes[1].fundrawtransaction, rawtx)

        #refill the keypool
        self.nodes[1].walletpassphrase("test", 100)
        self.nodes[1].keypoolrefill(8) #need to refill the keypool to get an internal change address
        self.nodes[1].walletlock()

        assert_raises_rpc_error(-13, "walletpassphrase", self.nodes[1].sendtoaddress, self.nodes[0].getnewaddress(), 1.2)

        oldBalance = self.nodes[0].getbalance()

        inputs = []
        outputs = {self.nodes[0].getnewaddress():1.1}
        rawtx = self.nodes[1].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[1].fundrawtransaction(rawtx)
        assert_greater_than(fundedTx['fee'], 0)

        #now we need to unlock
        self.nodes[1].walletpassphrase("test", 600)
        signedTx = self.nodes[1].signrawtransaction(fundedTx['hex'])
        txId = self.nodes[1].sendrawtransaction(signedTx['hex'])
        self.nodes[1].generate(1)
        self.sync_all()

        # make sure funds are received at node1
        assert_equal(oldBalance+Decimal('1.1'), self.nodes[0].getbalance())


        ###############################################
        # multiple (~19) inputs tx test | Compare fee #
        ###############################################

        #empty node1, send some small coins from node0 to node1
        fee = Decimal('0.0001')
        (burn1, burn2, rest) = BurnedAndChangeAmount(self.nodes[1].getbalance() - fee)
        txid = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), rest, "", "", True)
        verify_tx_sent(self.nodes[1], txid)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        for i in range(0,20):
            txid = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 0.01)
            verify_tx_sent(self.nodes[0], txid)
        self.nodes[0].generate(1)
        self.sync_all()

        #fund a tx with ~20 small inputs
        inputs = []
        outputs = {self.nodes[0].getnewaddress():0.15,self.nodes[0].getnewaddress():0.04}
        rawtx = self.nodes[1].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[1].fundrawtransaction(rawtx)
        assert_greater_than(fundedTx['fee'], 0)

        #create same transaction over sendtoaddress
        txId = self.nodes[1].sendmany("", outputs)
        verify_tx_sent(self.nodes[1], txId)
        signedFee = self.nodes[1].getrawmempool(True)[txId]['fee']

        #compare fee
        feeDelta = Decimal(fundedTx['fee']) - Decimal(signedFee)
        assert(feeDelta >= 0 and feeDelta <= feeTolerance*19) #~19 inputs


        #############################################
        # multiple (~19) inputs tx test | sign/send #
        #############################################

        #again, empty node1, send some small coins from node0 to node1
        fee = Decimal('0.0001')
        (burn1, burn2, rest) = BurnedAndChangeAmount(self.nodes[1].getbalance() - fee)
        txid = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), rest, "", "", True)
        verify_tx_sent(self.nodes[1], txid)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        for i in range(0,20):
            txid = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 0.01)
            verify_tx_sent(self.nodes[0], txid)
        self.nodes[0].generate(1)
        self.sync_all()

        #fund a tx with ~20 small inputs
        oldBalance = self.nodes[0].getbalance()

        inputs = []
        outputs = {self.nodes[0].getnewaddress():0.15,self.nodes[0].getnewaddress():0.04}
        rawtx = self.nodes[1].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[1].fundrawtransaction(rawtx)
        assert_greater_than(fundedTx['fee'], 0)
        fundedAndSignedTx = self.nodes[1].signrawtransaction(fundedTx['hex'])
        txId = self.nodes[1].sendrawtransaction(fundedAndSignedTx['hex'])
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()
        assert_equal(oldBalance+Decimal('0.19'), self.nodes[0].getbalance())

        #####################################################
        # test fundrawtransaction with OP_RETURN and no vin #
        #####################################################

        rawtx   = "0100000000010000000000000000066a047465737400000000"
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        assert_equal(len(dec_tx['vin']), 0)
        assert_equal(len(dec_tx['vout']), 1)

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        assert_greater_than(rawtxfund['fee'], 0)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        # print_tx_verbose(self.nodes[2], tx_json=dec_tx)
        assert_greater_than(len(dec_tx['vin']), 0) # at least one vin
        assert_equal(len(dec_tx['vout']), 2) # one change output added, no burn outputs: input_address == change_address
        parent_tx = self.nodes[2].getrawtransaction(dec_tx['vin'][0]['txid'], 1)
        return_output_index = find_output(self.nodes[2], None, 0, dec_tx)
        change_output_index = 1 - return_output_index
        change_address = dec_tx['vout'][change_output_index]['scriptPubKey']['addresses'][0]
        parent_vout = dec_tx['vin'][0]['vout']
        input_address = parent_tx['vout'][parent_vout]['scriptPubKey']['addresses'][0]
        assert_equal(input_address, change_address)

        ##################################################
        # test a fundrawtransaction using only watchonly #
        ##################################################

        watchonly_txid = self.nodes[0].sendtoaddress(watchonly_address, watchonly_amount)
        verify_tx_sent(self.nodes[0], watchonly_txid)
        self.nodes[0].generate(1)
        self.sync_all()

        inputs = []
        outputs = {self.nodes[2].getnewaddress() : watchonly_amount / 2}
        rawtx = self.nodes[3].createrawtransaction(inputs, outputs)

        result = self.nodes[3].fundrawtransaction(rawtx, {'includeWatching': True })
        assert_greater_than(result['fee'], 0)
        res_dec = self.nodes[0].decoderawtransaction(result["hex"])
        assert_equal(len(res_dec["vin"]), 1)
        assert_equal(res_dec["vin"][0]["txid"], watchonly_txid)

        assert("fee" in result.keys())
        assert_greater_than(result["changepos"], -1)

        ###############################################################
        # test fundrawtransaction using the entirety of watched funds #
        ###############################################################

        inputs = []
        outputs = {self.nodes[2].getnewaddress() : watchonly_amount}
        rawtx = self.nodes[3].createrawtransaction(inputs, outputs)

        # Backward compatibility test (2nd param is includeWatching)
        result = self.nodes[3].fundrawtransaction(rawtx, True)
        assert_greater_than(result['fee'], 0)
        res_dec = self.nodes[0].decoderawtransaction(result["hex"])
        assert_equal(len(res_dec["vin"]), 2)
        assert(res_dec["vin"][0]["txid"] == watchonly_txid or res_dec["vin"][1]["txid"] == watchonly_txid)

        spendable_unspents = [u for u in self.nodes[3].listunspent(1) if u['spendable']]
        watchonly_unspents = [u for u in self.nodes[3].listunspent(1) if not u['spendable']]
        assert_equal(len(spendable_unspents), 1)
        assert_equal(len(watchonly_unspents), 1)
        spendable_unspent = spendable_unspents[0]
        changepos = result["changepos"]
        assert_greater_than(result["fee"], 0)
        assert_greater_than(changepos, -1)
        change_address = res_dec['vout'][changepos]['scriptPubKey']['addresses'][0]

        grave_out1 = find_output_by_address(None, GRAVE_ADDRESS_1, tx_raw=res_dec)
        grave_out2 = find_output_by_address(None, GRAVE_ADDRESS_2, tx_raw=res_dec)
        grave_amount1 = res_dec["vout"][grave_out1]["value"]
        grave_amount2 = res_dec["vout"][grave_out2]["value"]
        assert_equal(result["fee"] + res_dec["vout"][result["changepos"]]["value"] + grave_amount1 + grave_amount2, watchonly_amount / 10)

        signedtx = self.nodes[3].signrawtransaction(result["hex"])
        assert(not signedtx["complete"])
        signedtx = self.nodes[0].signrawtransaction(signedtx["hex"])
        assert(signedtx["complete"])
        txid = self.nodes[0].sendrawtransaction(signedtx["hex"])
        if change_address != spendable_unspent['address']:
            # change is returned to watch-only address, that's what we don't expect,
            # spend it and send coins to normal node3 address instead:
            inputs = [{'txid': txid, 'vout': changepos}]
            amount_to = res_dec['vout'][changepos]['value'] - 2 - fee
            outputs = {AddressFromPubkeyHash(hash160(b'random')): amount_to, GRAVE_ADDRESS_1: 1, GRAVE_ADDRESS_2: 1}
            rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
            signedtx = self.nodes[0].signrawtransaction(rawtx)
            assert (signedtx['complete'])
            self.nodes[0].sendrawtransaction(signedtx['hex'])
            txid = self.nodes[0].sendtoaddress(spendable_unspent['address'], 20)
            verify_tx_sent(self.nodes[0], txid)
            self.log.debug('Refilled')
        self.nodes[0].generate(1)
        self.sync_all()

        #######################
        # Test feeRate option #
        #######################

        # Make sure there is exactly one input so coin selection can't skew the result
        assert_equal(len(self.nodes[3].listunspent(1)), 1)

        inputs = []
        outputs = {self.nodes[3].getnewaddress() : 1}
        rawtx = self.nodes[3].createrawtransaction(inputs, outputs)
        result = self.nodes[3].fundrawtransaction(rawtx, {"feeRate": 1*min_relay_tx_fee}) # uses min_relay_tx_fee (set by settxfee)
        result2 = self.nodes[3].fundrawtransaction(rawtx, {"feeRate": 2*min_relay_tx_fee})
        result3 = self.nodes[3].fundrawtransaction(rawtx, {"feeRate": 10*min_relay_tx_fee})
        assert_greater_than(result['fee'], 0)
        assert_greater_than(result2['fee'], 0)
        assert_greater_than(result3['fee'], 0)
        result_fee_rate = result['fee'] * 1000 / count_bytes(result['hex'])
        assert_fee_amount(result2['fee'], count_bytes(result2['hex']), 2 * result_fee_rate)
        assert_fee_amount(result3['fee'], count_bytes(result3['hex']), 10 * result_fee_rate)

        ################################
        # Test no address reuse occurs #
        ################################

        result3 = self.nodes[3].fundrawtransaction(rawtx)
        assert_greater_than(result3['fee'], 0)
        res_dec = self.nodes[0].decoderawtransaction(result3["hex"])
        changeaddress = ""
        for out in res_dec['vout']:
            if out['value'] > 1.0:
                changeaddress += out['scriptPubKey']['addresses'][0]
        assert(changeaddress != "")
        nextaddr = self.nodes[3].getnewaddress()
        # Now the change address key should be removed from the keypool
        assert(changeaddress != nextaddr)

        ######################################
        # Test subtractFeeFromOutputs option #
        ######################################

        # Make sure there is exactly one input so coin selection can't skew the result
        assert_equal(len(self.nodes[3].listunspent(1)), 1)

        inputs = []
        dest_addr = self.nodes[2].getnewaddress()
        outputs = {dest_addr: 1}
        rawtx = self.nodes[3].createrawtransaction(inputs, outputs)

        result = [self.nodes[3].fundrawtransaction(rawtx), # uses min_relay_tx_fee (set by settxfee)
                  self.nodes[3].fundrawtransaction(rawtx, {"subtractFeeFromOutputs": []}), # empty subtraction list
                  self.nodes[3].fundrawtransaction(rawtx, {"subtractFeeFromOutputs": [0]}), # uses min_relay_tx_fee (set by settxfee)
                  self.nodes[3].fundrawtransaction(rawtx, {"feeRate": 2*min_relay_tx_fee}),
                  self.nodes[3].fundrawtransaction(rawtx, {"feeRate": 2*min_relay_tx_fee, "subtractFeeFromOutputs": [0]})]
        [assert_greater_than(re['fee'], 0) for re in result]

        dec_tx = [self.nodes[3].decoderawtransaction(tx['hex']) for tx in result]
        output = [d['vout'][find_output_by_address(None, dest_addr, tx_raw=d)]['value'] for d in dec_tx]
        change = [d['vout'][r['changepos']]['value'] for d, r in zip(dec_tx, result)]
        burned = [d['vout'][find_output_by_address(None, GRAVE_ADDRESS_1, tx_raw=d)]['value'] +
                  d['vout'][find_output_by_address(None, GRAVE_ADDRESS_2, tx_raw=d)]['value'] for d in dec_tx]

        assert_equal(result[0]['fee'], result[1]['fee'], result[2]['fee'])
        assert_equal(result[3]['fee'], result[4]['fee'])
        assert_equal(change[0], change[1])
        assert_equal(output[0], output[1])
        assert_equal(output[0], output[2] + result[2]['fee'] + burned[2])
        assert_equal(change[0] + result[0]['fee'] + burned[0], change[2])
        assert_equal(output[3], output[4] + result[4]['fee'] + burned[4])
        assert_equal(change[3] + result[3]['fee'] + burned[3], change[4])

        inputs = []
        outputs = {self.nodes[2].getnewaddress(): value for value in (1.0, 1.1, 1.2, 1.3)}
        rawtx = self.nodes[3].createrawtransaction(inputs, outputs)

        result = [self.nodes[3].fundrawtransaction(rawtx),
                  # split the fee between outputs 0, 2, and 3, but not output 1
                  self.nodes[3].fundrawtransaction(rawtx, {"subtractFeeFromOutputs": [0, 2, 3]})]
        [assert_greater_than(re['fee'], 0) for re in result]

        dec_tx = [self.nodes[3].decoderawtransaction(result[0]['hex']),
                  self.nodes[3].decoderawtransaction(result[1]['hex'])]

        # Nested list of non-change output amounts for each transaction
        output = [[out['value'] for out in d['vout'] if out['scriptPubKey']['addresses'][0] in outputs]
                  for d in dec_tx]
        burned = [[out['value'] for out in d['vout'] if out['scriptPubKey']['addresses'][0] in [GRAVE_ADDRESS_1, GRAVE_ADDRESS_2]]
                  for d in dec_tx]
        burned_total = [sum(bur_outputs) for bur_outputs in burned]

        # List of differences in output amounts between normal and subtractFee transactions
        share = [o0 - o1 for o0, o1 in zip(output[0], output[1])]

        # output 1 is the same in both transactions
        assert_equal(share[1], 0)

        # the other 3 outputs are smaller as a result of subtractFeeFromOutputs
        assert_greater_than(share[0], 0)
        assert_greater_than(share[2], 0)
        assert_greater_than(share[3], 0)

        # outputs 2 and 3 take the same share of the fee
        assert_equal(share[2], share[3])

        # output 0 takes at least as much share of the fee, and no more than 2 satoshis more, than outputs 2 and 3
        assert_greater_than_or_equal(share[0], share[2])
        assert_greater_than_or_equal(share[2] + Decimal(2e-8), share[0])

        # the fee is the same in both transactions
        assert_equal(result[0]['fee'], result[1]['fee'])

        # the total subtracted from the outputs is equal to the fee
        assert_equal(share[0] + share[2] + share[3], result[0]['fee'] + burned_total[1])

if __name__ == '__main__':
    RawTransactionsTest().main()
