from keymanager import KeyManager as km
import requests
import mythril
import hashlib
import pandas as pd
import time
from datetime import timedelta,datetime

###python 3.9.0 required for mythril

#below is a temporary function for measuring runtime while optimizing
global timer, timeIt
timer={}

def timeIt(start_time,name):
    end_time = time.monotonic()
    duration=timedelta(seconds=end_time - start_time).total_seconds()
    if name in timer.keys():
        timer[name]=timer[name]+duration
    else: timer[name]=duration
#####


class Gene:

    def __init__(self):
        pass

    def hashOpcode(self,bytecode):
        oplist=[]
        opl = mythril.disassembler.asm.disassemble(bytecode)
        for op in opl:
            oplist.append(op['opcode'])
        return hashlib.sha1(bytes("".join(oplist),encoding='UTF-8')).hexdigest()

    def getParent(self,address):
        start_time=time.monotonic()
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
                timeIt(start_time,"getParent")
                return result[0]['contractCreator']
            if content[0]['traceId'].count("_")==0:
                timeIt(start_time,"getParent")
                return result[0]['contractCreator']
            else:
                timeIt(start_time,"getParent")
                return content[0]['from']

    def checkNormal(self,address,creationdict,transactionlimit,requestbypass):
        start_time=time.monotonic()
        if requestbypass==None:
            payload=payload="""
                https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=asc&apikey={apikey}&offset={offset}&page=1
                """
            content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address,offset=transactionlimit))
            content=content.json()['result']
        else: content=requestbypass
        address=address.lower()
        for txn in content:
            if (txn["value"]=="0" and txn["to"]=="") and txn["from"]==address:
                if address in creationdict.keys():
                    if txn['contractAddress'] not in creationdict[txn['from']]:
                        creationdict[txn['from']].append(txn['contractAddress'])
                else: creationdict[txn['from']]=[txn['contractAddress']]
        timeIt(start_time,"checkNormal")
        return creationdict

    def getHashes(self,address,transactionlimit,creationdict):
        start_time=time.monotonic()
        payload=payload="""
            https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=asc&apikey={apikey}&offset={offset}&page=1
            """
        content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address,offset=transactionlimit))
        required=[]
        for txn in content.json()['result']:
            if txn["isError"]=="0":
                creationdict=Gene().checkNormal(address,txn,creationdict)
                required.append(txn['hash'])
        timeIt(start_time,"getHashes")
        return required,creationdict

    def checkOpcode(self,address,creationdict,transactionlimit,requestbypass):
        start_time=time.monotonic()
        if requestbypass==None:
            content=requests.get("https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=asc&apikey={apikey}&offset={offset}&page=1".format(address=address,offset=transactionlimit,apikey=km().Easy_Key("etherscan_api_key"))).json()
            content=content['result']
        else: content=requestbypass
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
        timeIt(start_time,"checkOpcode")
        return creationdict

    def normInternal(self,address,creationdict,transactionlimit):
        start_time=time.monotonic()
        hashes,creationdict=Gene().getHashes(address,transactionlimit,creationdict)
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
        timeIt(start_time,"normInternal")
        return creationdict

    def contractInternal(self,address,creationdict,transactionlimit):
        start_time=time.monotonic()
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
        timeIt(start_time,"contractInternal")
        return creationdict

    def multiCheck(self,address,creationdict,transactionlimit):
        start_time=time.monotonic()
        payload=payload="""
            https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=asc&apikey={apikey}&offset={offset}&page=1
            """
        content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address,offset=transactionlimit))
        content=content.json()['result']
        creationdict=Gene().checkNormal(address,creationdict,transactionlimit,content)
        creationdict=Gene().contractInternal(address,creationdict,transactionlimit)
        #creationdict=Gene().normInternal(address,creationdict,transactionlimit)
        creationdict=Gene().checkOpcode(address,creationdict,transactionlimit,content)
        timeIt(start_time,"multiCheck")
        return creationdict

    def getHighest(self,creationdict):
        start_time=time.monotonic()
        masterlist=[]
        for lists in creationdict.values():
            masterlist.extend(lists)

        keylist=list(creationdict.keys())

        for val in masterlist:
            if val in keylist:
                keylist.remove(val)
        #print(keylist)
        timeIt(start_time,"getHighest")
        return keylist[0]

    def climb(self,address):
        start_time=time.monotonic()
        while True:
            lastaddress=address
            address=Gene().getParent(lastaddress)
            if address==None or address==lastaddress:
                timeIt(start_time,"climb")
                return lastaddress

    def flatDict(self,dicto):
        start_time=time.monotonic()
        flatlist=list(dicto.keys())
        values=list(dicto.values())
        for value in values:
            flatlist.extend(value)
        flatlist=list(dict.fromkeys(flatlist))
        flatlist2=flatlist
        for x in range(flatlist.count("")):
            flatlist2.remove("")
        timeIt(start_time,"flatDict")
        return flatlist2

    def trickleDown(self,address,creationdict,transactionlimit):
        start_time=time.monotonic()
        creationdict=Gene().multiCheck(address,creationdict,transactionlimit)
        flat=1
        newflat=2
        while flat!=newflat:
            flat=Gene().flatDict(creationdict)
            for addr in flat:
                if newflat!=2:
                    if addr in newflat:
                        continue
                    else: creationdict=Gene().multiCheck(addr,creationdict,transactionlimit)
                else: creationdict=Gene().multiCheck(addr,creationdict,transactionlimit)
            newflat=Gene().flatDict(creationdict)
        timeIt(start_time,"trickleDown")
        return creationdict

    def getABI(self,address):
        start_time = time.monotonic()
        payload=payload="""
            https://api.etherscan.io/api?module=contract&action=getabi&address={address}&apikey={apikey}
            """
        content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address))
        content=content.json()['result']
        if content=="Contract source code not verified":
            content="UNVERIFIED"
        timeIt(start_time,"getABI")
        return content

    def uniqueContracts(self,creationdict,uniquesource):
        start_time = time.monotonic()
        flattenned=Gene().flatDict(creationdict)
        returnable={}
        for addr in flattenned:
            url="https://eth-mainnet.g.alchemy.com/v2/{apikey}".format(apikey=km().Easy_Key("alchemy-key"))
            payload={
                "id": 1,
                "jsonrpc": "2.0",
                "method": "eth_getCode"
            }
            payload["params"]=[addr, "latest"]
            headers={
                "accept": "application/json",
                "content-type": "application/json"
            }
            source = requests.post(url, json=payload, headers=headers).json()
            source=source['result']
            # source=response['result'].join("")
            # source=mythril.disassembler.asm.disassemble(source)
            if source!="":
                hashed=Gene().hashOpcode(source)
                if uniquesource==True:
                    if hashed not in returnable.keys():
                        returnable[addr]=hashed
                else:
                    returnable[addr]=hashed
            else:
                returnable[addr]="EOA"
        timeIt(start_time,"uniqueContracts")
        #print(returnable)
        return returnable

    def masterSleuth(self,address,savefile,transactionlimit,uniquesource):
        start_time=time.monotonic()
        address=Gene().climb(address)
        creationdict=Gene().trickleDown(address,{},transactionlimit)
        sourcehashes=Gene().uniqueContracts(creationdict,uniquesource)
        address_string=Gene().flatDict(creationdict)
        contracts=[]
        eoas=[]
        children_eoa=[]
        parent_eoa=[]
        parent=[]
        children=[]
        for addr in address_string:
            addr=addr.lower()
            if sourcehashes[addr]=="EOA":
                print(addr)
                eoas.append(addr)
                if addr in creationdict.keys():
                    children_eoa.append(creationdict[addr])
                else:
                    children_eoa.append("[]")
                for key in list(creationdict.keys()):
                    valuelist=creationdict[key]
                    #print(valuelist)
                    if addr in valuelist:
                        parent_eoa.append(key)
                        toggle=False
                        break
                    else:
                        toggle=True
                if toggle:
                    parent_eoa.append(None)
            else:
                contracts.append(addr)
                if addr in creationdict.keys():
                    children.append(creationdict[addr])
                else:
                    children.append("[]")
                for key in list(creationdict.keys()):
                    valuelist=creationdict[key]
                    #print(valuelist)
                    if addr in valuelist:
                        parent.append(key)
                        toggle=False
                        break
                    else:
                        toggle=True
                if toggle:
                    parent.append(None)
        #print(creationdict)
        df=pd.DataFrame(data={"address:string":contracts,"parent:string":parent,"children:list":children})
        df['~label']="CONTRACT"
        df['sourceHash:string']=df['address:string'].map(sourcehashes)
        sourcehashes=list(set(sourcehashes.values()))
        if "EOA" in sourcehashes:
            sourcehashes.remove("EOA")
        for hash in sourcehashes:
            df.loc[df["sourceHash:string"] == hash, "abi:string"] = Gene().getABI(df[df['sourceHash:string']==hash]['address:string'].to_list()[0])
        if len(df['sourceHash:string'])<1:
            df["abi:string"]=None
        df["~id"]="eth:"+df["address:string"].astype("str")
        df=df[["~id","~label","address:string","abi:string","sourceHash:string","parent:string","children:list"]]
        df.to_csv(savefile+"_contracts.csv")
        df_eoa=pd.DataFrame(data={"address:string":eoas,"parent:string":parent_eoa,"children:list":children_eoa})
        df_eoa['~id']="eth:"+df_eoa["address:string"].astype("str")
        df_eoa['~label']="EOA"
        df_eoa=df_eoa[["~id","~label","address:string","parent:string","children:list"]]
        df_eoa.to_csv(savefile+"_EOAs.csv")
        #abi_string.append(Gene().getABI(addr))
        timeIt(start_time,"masterSleuth")
        
#Example Usage
# Gene().masterSleuth('0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f','univ2',100,False)
# print(timer)