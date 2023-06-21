from keymanager import KeyManager as km
import requests
import json
import dis
import mythril

###python 3.9.0 required for mythril

def GetAllHashesFromAddress(address):
    payload=payload="""
        https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=asc&apikey={apikey}
        """
    content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address))
    required=[]
    for txn in content.json()['result']:
        required.append(txn['hash'])
    return required

def Check_Opcode(address,creationdict):
    content=requests.get("https://api.etherscan.io/api?module=account&action=txlist&address={address}&apikey={apikey}".format(address=address,apikey=km().Easy_Key("etherscan_api_key"))).json()
    content=content['result']
    for i in content:
        txn=i['input']
        opl = mythril.disassembler.asm.disassemble(txn)
        for op in opl:
            if op['opcode'] in ["CREATE","CREATE2"]:
                if i['contractAddress']!="":
                    if i['from'] in creationdict.keys():
                        creationdict[i['from']].append(i['contractAddress'])
                    else: creationdict[i['from']]=[i['contractAddress']]
    return creationdict

def Check_Normal_By_Internal(address,creationdict):
    hashes=GetAllHashesFromAddress(address)
    #creator=
    payload="""
        https://api.etherscan.io/api?module=account&action=txlistinternal&txhash={hash}&apikey={apikey}&sort=asc
        """
    for hash in hashes:
        content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),hash=hash))
        for txn in content.json()['result']:
            if txn['type'] in ['create','create2']:
                if txn['from'] in creationdict.keys():
                    creationdict[txn['from']].append(txn['contractAddress'])
                else: creationdict[txn['from']]=[txn['contractAddress']]
    return creationdict

def Check_Contract_Internal(address,creationdict):
    payload="""
        https://api.etherscan.io/api?module=account&action=txlistinternal&address={address}&sort=asc&apikey={apikey}
        """
    content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address))
    for txn in content.json()['result']:
        if txn['type'] in ['create','create2']:
            if txn['from'] in creationdict.keys():
                creationdict[txn['from']].append(txn['contractAddress'])
            else: creationdict[txn['from']]=[txn['contractAddress']]
            creationdict[txn['contractAddress']]=txn['from']
    return creationdict

def MultiCheck(address):
    creationdict=Check_Contract_Internal(address,{})
    creationdict=Check_Normal_By_Internal(address,creationdict)
    creationdict=Check_Opcode(address,creationdict)
    return creationdict

print(MultiCheck("0xD1C24f50d05946B3FABeFBAe3cd0A7e9938C63F2"))


