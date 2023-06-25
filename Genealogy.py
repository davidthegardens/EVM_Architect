from keymanager import KeyManager as km
import requests
import json
import dis
import mythril

###python 3.9.0 required for mythril

def GetParent(address):
    payload="https://api.etherscan.io/api?module=contract&action=getcontractcreation&contractaddresses={address}&apikey={apikey}"
    content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address))
    result=content.json()['result']
    if result==None or result[0]['contractCreator']==address:
        return None
    else:
        payload="""
            https://api.etherscan.io/api?module=account&action=txlistinternal&address={address}&apikey={apikey}&sort=asc&offset={offset}&txhash={hash}&page=1
            """
        content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address,offset=1,hash=result[0]['txHash']))
        content=content.json()['result']
        if len(content)<1:
            return result[0]['contractCreator']
        if content[0]['traceId'].count("_")==0:
            return result[0]['contractCreator']
        else:
            return content[0]['from']


print(GetParent('0xb7B4B6D077fc59E6387C3c4ff9a9a6BE031d1dfE'))
print(GetParent("0xc0a47dfe034b400b47bdad5fecda2621de6c4d95"))

def FactoryCheck():

    return

def CheckNormal(address,txn,creationdict):
    address=address.lower()
    if (txn["value"]=="0" and txn["to"]=="") and txn["from"]==address:
        if address in creationdict.keys():
            if txn['contractAddress'] not in creationdict[txn['from']]:
                creationdict[txn['from']].append(txn['contractAddress'])
        else: creationdict[txn['from']]=[txn['contractAddress']]
    return creationdict

def GetAllHashesFromAddress(address,transactionlimit,creationdict):
    payload=payload="""
        https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=asc&apikey={apikey}&offset={offset}&page=1
        """
    content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address,offset=transactionlimit))
    required=[]
    for txn in content.json()['result']:
        if txn["isError"]=="0":
            creationdict=CheckNormal(address,txn,creationdict)
            required.append(txn['hash'])
    return required,creationdict

#print(GetAllHashesFromAddress("0x51F22ac850D29C879367A77D241734AcB276B815",100,{})[1])

def Check_Opcode(address,creationdict,transactionlimit):
    content=requests.get("https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=asc&apikey={apikey}&offset={offset}&page=1".format(address=address,offset=transactionlimit,apikey=km().Easy_Key("etherscan_api_key"))).json()
    content=content['result']
    for i in content:
        txn=i['input']
        opl = mythril.disassembler.asm.disassemble(txn)
        for op in opl:
            if op['opcode'] in ["CREATE","CREATE2"]:
                if i['contractAddress']!="":
                    if i['from'] in creationdict.keys():
                        if i['contractAddress'] not in creationdict[i['from']]:
                            creationdict[i['from']].append(i['contractAddress'])
                    else: creationdict[i['from']]=[i['contractAddress']]
    return creationdict

def Check_Normal_By_Internal(address,creationdict,transactionlimit):
    hashes,creationdict=GetAllHashesFromAddress(address,transactionlimit,creationdict)
    #creator=
    payload="""
        https://api.etherscan.io/api?module=account&action=txlistinternal&txhash={hash}&apikey={apikey}&sort=asc&offset={offset}&page=1
        """
    for hash in hashes:
        content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),hash=hash,offset=transactionlimit))
        for txn in content.json()['result']:
            if txn['type'] in ['create','create2']:
                if txn['from'] in creationdict.keys():
                    if txn['contractAddress'] not in creationdict[txn['from']]:
                        creationdict[txn['from']].append(txn['contractAddress'])
                else: creationdict[txn['from']]=[txn['contractAddress']]
    return creationdict

def Check_Contract_Internal(address,creationdict,transactionlimit):
    payload="""
        https://api.etherscan.io/api?module=account&action=txlistinternal&address={address}&sort=asc&apikey={apikey}&offset={offset}&page=1
        """
    content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address,offset=transactionlimit))
    for txn in content.json()['result']:
        if txn['type'] in ['create','create2']:
            if txn['from'] in creationdict.keys():
                if txn['contractAddress'] not in creationdict[txn['from']]:
                    creationdict[txn['from']].append(txn['contractAddress'])
            else: creationdict[txn['from']]=[txn['contractAddress']]
            #creationdict[txn['contractAddress']]=txn['from']
    return creationdict

def MultiCheck(address,creationdict,transactionlimit):
    creationdict=Check_Contract_Internal(address,creationdict,transactionlimit)
    creationdict=Check_Normal_By_Internal(address,creationdict,transactionlimit)
    creationdict=Check_Opcode(address,creationdict,transactionlimit)
    return creationdict

def GetHighest(creationdict):
    masterlist=[]
    for lists in creationdict.values():
        masterlist.extend(lists)

    keylist=list(creationdict.keys())

    for val in masterlist:
        if val in keylist:
            keylist.remove(val)
    print(keylist)
    return keylist[0]

def Climb(address):
    while True:
        lastaddress=address
        address=GetParent(lastaddress)
        if address==None or address==lastaddress:
            return lastaddress

def flatdict(dicto):
    flatlist=list(dicto.keys())
    values=list(dicto.values())
    for value in values:
        flatlist.extend(value)
    return list(dict.fromkeys(flatlist))

def TrickleDown(address,creationdict,transactionlimit):
    creationdict=MultiCheck(address,creationdict,transactionlimit)
    flat=1
    newflat=2
    while flat!=newflat:
        print(1)
        flat=flatdict(creationdict)
        for addr in flat:
            if newflat!=2:
                if addr in newflat:
                    continue
                else: creationdict=MultiCheck(addr,creationdict,transactionlimit)
            else: creationdict=MultiCheck(addr,creationdict,transactionlimit)
        newflat=flatdict(creationdict)
    return creationdict

#print(TrickleDown("0x51F22ac850D29C879367A77D241734AcB276B815",{},80))

print(Climb('0xce680723d7fd67ab193dfec828b7fbc441f29b01'))