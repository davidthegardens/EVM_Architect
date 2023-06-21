from etherscan_py import etherscan_py
import keymanager
# from ape import accounts, Contract
# import os
# os.environ["ETHERSCAN_API_KEY"]="xxxx"

# contract = Contract("0x55a8a39bc9694714e2874c1ce77aa1e599461e18")
# receipt = contract.call_mutable_method("arg0", sender=accounts.load("acct"))
# client = etherscan_py.Client("xxxx")
# firstblock=client.get_all_events(address="0x4e395304655F0796bc3bc63709DB72173b9DdF98")
# print(firstblock)

# from etherscan import Etherscan
# eth = etherscan("xxxx")

# eth.get_eth_balance(address="0xddbd2b932c763ba5b1b7ae3b362eac3e8d40121a")

import requests
import pickle
import json
import os

creation_methods=["0x6103f056"]
address="0xb7B4B6D077fc59E6387C3c4ff9a9a6BE031d1dfE"
apikey="xxxx"

def initialize(coerce):

    if coerce==True:
        payload="""
        https://api.etherscan.io/api?module=account&action=txlistinternal&address={address}&startblock=0&endblock=99999999&sort=dsc&apikey={apikey}
        """
        content=requests.get(payload.format(apikey=apikey,address=address))
        childaddresses=[]
        creationblock=[]
        creationtxn=[]
        for txn in content.json()['result']:
            print(txn)
            break
            if txn["from"]==address.lower() and txn["isError"]=="0" and txn["type"]=="create":
                childaddresses.append(txn["contractAddress"])
                creationblock.append(txn["blockNumber"])
                creationtxn.append(txn["hash"])
        
        #print(childaddresses)


        with open("data.pickle","wb") as f:
            pickle.dump(content.json()['result'],f)

#initialize(True)

def FindParent(address):
    payload="""
    https://api.etherscan.io/api?module=account&action={action}&address={address}&startblock=0&endblock=99999999&sort=asc&page=1&offset=1&apikey={apikey}
    """
    contentin=requests.get(payload.format(apikey=apikey,address=address,action="txlistinternal")).json()['result']
    contentnorm=requests.get(payload.format(apikey=apikey,address=address,action="txlist")).json()['result'][0]
    if len(contentin)<1 or (int(contentin[0]["timeStamp"])>=int(contentnorm["timeStamp"])):
        content=contentnorm
    else:
        content=contentin[0]
    if content["contractAddress"]==address.lower() and content["to"]=="" and content["value"]=="0":
        return content["from"]
    else:
        #print(content) 
        return "Orphan"
        # for txn in blob:
        #     if txn["hash"]=="0xc1b2646d0ad4a3a151ebdaaa7ef72e3ab1aa13aa49d0b7a3ca020f5ee7b1b010":
        #         print(txn)
        #     if txn["contractAddress"]==address.lower() and txn["type"]=="create" and txn["isError"]=="0":
        #         print(txn["from"])

#FindParent(address)

def FindChildren(address):
    payload="""
    https://api.etherscan.io/api?module=account&action={action}&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={apikey}
    """
    content=requests.get(payload.format(apikey=apikey,address=address,action="txlistinternal"))
    childaddresses=[]
    results=content.json()['result']
    if len(results)>=50:
        return ["factory"]
    for txn in results:
        if txn["from"]==address.lower() and txn["isError"]=="0" and txn["type"]=="create":
            childaddresses.append(txn["contractAddress"])
    content=requests.get(payload.format(apikey=apikey,address=address,action="txlist"))
    for txn in content.json()['result']:    content=requests.get(payload.format(apikey=apikey,address=address,action="txlist"))
    for txn in content.json()['result']:
        if txn["to"]=="" and txn["value"]=="0" and txn["isError"]=="0" and txn["from"]==address.lower():
            if FindParent(txn["contractAddress"])==address.lower():
                childaddresses.append(txn["contractAddress"])
                print(txn)
        if txn["to"]=="" and txn["value"]=="0" and txn["isError"]=="0" and txn["from"]==address.lower() and txn["methodId"] in creation_methods:
            if FindParent(txn["contractAddress"])==address.lower():
                childaddresses.append(txn["contractAddress"])
    return childaddresses

# print(FindChildren('0xd1c24f50d05946b3fabefbae3cd0a7e9938c63f2'))

def TreeClimber(startaddress):
    address=startaddress
    for i in range(10):
        try:
            beforeaddress=address
            address=FindParent(address)
            if address=="Orphan":
                return beforeaddress
            print(beforeaddress,"->",address)
        except IndexError:
            return address


def FamilyTree(address):
    matriarch=TreeClimber(address)
    visitedlist=[]
    newgen=FindChildren(matriarch)
    for i in range(3):
        for child in newgen:
            if child in visitedlist:
                continue
            newgen=FindChildren(child)
            visitedlist.append(child)
        print(visitedlist)


FamilyTree(address)

"""https://api.etherscan.io/api
   ?module=account
   &action=txlistinternal
   &address=0xc5102fE9359FD9a28f877a67E36B0F050d81a3CC
   &startblock=0
   &endblock=99999999
   &page=1
   &offset=10
   &sort=asc
   &apikey=YourApiKeyToken"""


# client = etherscan_py.Client("xxxx")
# firstblock=client.get_events(address="0xc0a47dfe034b400b47bdad5fecda2621de6c4d95",to_block=6627917,topic="")
# print(firstblock)

#initialize(True)
# with open 
# content=pickle.load("data.pickle",)