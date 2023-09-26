from keymanager import KeyManager as km
import requests
import mythril
import hashlib
from web3 import Web3
from multiprocessing.pool import ThreadPool

### use web3==5.31.1 and python 3.9.0

global w
w=Web3(Web3.HTTPProvider(km().Easy_Key('archive_node_url')))

class Arch:
    
    def __init__(self):
        pass
    
    def mergeDict(self,dicts):
        dict_z=dicts[0]
        for x in range(1,len(dicts)):
            for key in dicts[x].keys():
                if key in dict_z:
                    if dict_z[key]==dicts[x][key]:
                        continue
                    else:
                        dict_z[key].extend(dicts[x][key])
                        dict_z[key]=list(set(dict_z[key]))
                else:
                    dict_z[key]=dicts[x][key]
        return dict_z

    def getCode_reth(self,addr):
        return w.eth.get_code(Web3.toChecksumAddress(addr)).hex()

    def hashOpcode(self,bytecode):
        oplist=[]
        opl = mythril.disassembler.asm.disassemble(bytecode)
        for op in opl:
            oplist.append(op['opcode'])
        return hashlib.sha1(bytes("".join(oplist),encoding='UTF-8')).hexdigest()

    def getParent(self,address):
        payload="https://api.etherscan.io/api?module=contract&action=getcontractcreation&contractaddresses={address}&apikey={apikey}"
        content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address))
        result=content.json()['result']
        try:
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
        except Exception:
            print(result)
            return None

    def checkNormal(self,address,creationdict,transactionlimit,requestbypass):
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
        return creationdict

    def checkOpcode(self,address,creationdict,transactionlimit,requestbypass):
        ### in the near future, change this over to look at bytes from cryo txs db similar to banteg's proxy checking method https://banteg.xyz/posts/minimal-proxies/
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
        return creationdict

    def contractInternal(self,address,creationdict,transactionlimit):
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
        return creationdict

    def multiCheck(self,address,creationdict,transactionlimit):
        payload="""
            https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=asc&apikey={apikey}&offset={offset}&page=1
            """
        content=requests.get(payload.format(apikey=km().Easy_Key(KeyName="etherscan_api_key"),address=address,offset=transactionlimit))
        content=content.json()['result']
        pool = ThreadPool(processes=3)
        norm=Arch().checkNormal
        inter=Arch().contractInternal
        checkopc=Arch().checkOpcode
        norm_result = pool.apply_async(norm, (address,creationdict,transactionlimit,content))
        norm_creationdict=norm_result.get()
        inter_result = pool.apply_async(inter,(address,creationdict,transactionlimit))
        inter_creationdict=inter_result.get()
        checkopc_result = pool.apply_async(checkopc, (address,creationdict,transactionlimit,content))
        checkopc_creationdict=checkopc_result.get()
        creationdict=Arch().mergeDict([norm_creationdict,inter_creationdict,checkopc_creationdict])
        return creationdict

    def getHighest(self,creationdict):
        #returns the highest member in the architecture
        masterlist=[]
        for lists in creationdict.values():
            masterlist.extend(lists)

        keylist=list(creationdict.keys())

        for val in masterlist:
            if val in keylist:
                keylist.remove(val)
        return keylist[0]

    def climb(self,address):
        while True:
            lastaddress=address
            address=Arch().getParent(lastaddress)
            if address==None or address==lastaddress:
                return lastaddress

    def flatDict(self,dicto):
        flatlist=list(dicto.keys())
        values=list(dicto.values())
        for value in values:
            flatlist.extend(value)
        flatlist=list(dict.fromkeys(flatlist))
        flatlist2=flatlist
        for x in range(flatlist.count("")):
            flatlist2.remove("")
        return flatlist2

    def trickleDown(self,address,creationdict,transactionlimit):
        creationdict=Arch().multiCheck(address,creationdict,transactionlimit)
        flat=1
        newflat=2
        while flat!=newflat:
            flat=Arch().flatDict(creationdict)
            for addr in flat:
                if newflat!=2:
                    if addr in newflat:
                        continue
                    else: creationdict=Arch().multiCheck(addr,creationdict,transactionlimit)
                else: creationdict=Arch().multiCheck(addr,creationdict,transactionlimit)
            newflat=Arch().flatDict(creationdict)
        return creationdict

    def uniqueContracts(self,creationdict,uniquesource):
        #returns a dictionary of {address: hash of opcode stack} using every address in the creationdict
        flattenned=Arch().flatDict(creationdict)
        returnable={}
        for addr in flattenned:
            source=Arch().getCode_reth(addr)
            if source!="":
                hashed=Arch().hashOpcode(source)
                if uniquesource==True:
                    if hashed not in returnable.keys():
                        returnable[addr]=hashed
                else:
                    returnable[addr]=hashed
            else:
                returnable[addr]="EOA"
        return returnable

    def getArch(self,address,transactionlimit,flat):
        address=Arch().climb(address)
        creationdict=Arch().trickleDown(address,{},transactionlimit)
        if flat:
            return Arch().flatDict(creationdict)
        else:
            return creationdict
    


