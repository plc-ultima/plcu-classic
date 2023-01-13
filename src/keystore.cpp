// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keystore.h"

#include "key.h"
#include "plcvalidator.h"
#include "pubkey.h"
#include "util.h"

CKeyStore::~CKeyStore() 
{
}

bool CKeyStore::AddKey(const CKey &key) {
    return AddKeyPubKey(key, key.GetPubKey());
}

bool CBasicKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key)) {
        LOCK(cs_KeyStore);
        WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
        if (it != mapWatchKeys.end()) {
            vchPubKeyOut = it->second;
            return true;
        }
        return false;
    }
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
        return error("CBasicKeyStore::AddCScript(): redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    //TODO: Use Solver to extract this?
    CScript::const_iterator pc = dest.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    if (!dest.GetOp(pc, opcode, vch) || vch.size() < 33 || vch.size() > 65)
        return false;
    pubKeyOut = CPubKey(vch);
    if (!pubKeyOut.IsFullyValid())
        return false;
    if (!dest.GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG || dest.GetOp(pc, opcode, vch))
        return false;
    return true;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys[pubKey.GetID()] = pubKey;
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.erase(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys.erase(pubKey.GetID());
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

//******************************************************************************
//******************************************************************************
bool CBasicKeyStore::hasTaxFreeCert() const
{
    return (m_taxFreeParams.flags & plc::shadowEmperor) == plc::shadowEmperor;
}

//******************************************************************************
//******************************************************************************
bool CBasicKeyStore::getCert(std::vector<std::vector<unsigned char> > & pubkeys,
                             std::vector<plc::Certificate> & certs) const
{
    if (m_taxfreePubkeys.empty() || m_taxfreeCerts.empty())
    {
        // not loaded
        return false;
    }

    pubkeys = m_taxfreePubkeys;
    certs   = m_taxfreeCerts;
    return true;
}

//******************************************************************************
//******************************************************************************
bool CBasicKeyStore::setCert(const std::vector<std::vector<unsigned char> > & pubkeys,
                             const std::vector<plc::Certificate> & certs)
{
    plc::CertParameters params;
    if (!plc::Validator().validateChainOfCerts(certs, pubkeys, params))
    {
        resetCert();
        return false;
    }
    m_taxfreePubkeys = pubkeys;
    m_taxfreeCerts   = certs;
    m_taxFreeParams  = params;
    return true;
}

//******************************************************************************
//******************************************************************************
void CBasicKeyStore::resetCert()
{
    m_taxfreePubkeys.clear();
    m_taxfreeCerts.clear();
    m_taxFreeParams = plc::CertParameters();
}

//******************************************************************************
//******************************************************************************
bool CDummyKeyStore::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    if (CBasicKeyStore::GetPubKey(address, vchPubKeyOut))
    {
        return true;
    }

    // dummy compressed pub key
    static const std::vector<unsigned char> vch(33, 0x02);
    // vch[0] = 0x02;
    vchPubKeyOut.Set(vch.begin(), vch.end());
    return true;
}

