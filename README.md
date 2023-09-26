# EVM_Architect
There's a handful of optimizations still to be had. Speed has been increased by using a rpc provider rather than etherscan for getCode, and the multicheck function is now multithreaded so that all the checks occur simultaneaously. The following is an example of how to get a flat list of entities in an architecture, given a single address.

To use this, make sure you're using python 3.9.0. You can install using pip.

```Python
pip install EVM_Architect
```

Most of the time you'll probably just want to use getArch(), these are the arguments:

```Python
getArch(
    address-string, 
    transaction_limit-int, 
    flatten-bool)
```

If flatten==True, then you will get a list of addresses (EOAs and contracts).

```Python
#Example:
['0xd1c24f50d05946b3fabefbae3cd0a7e9938c63f2', '0xc0a47dfe034b400b47bdad5fecda2621de6c4d95', '0xa087b7351c24082ac7ef7ca79b4f4c5d2e82be84', '0x2157a7894439191e520825fe9399ab8655e0f708', '0x2c4bd064b998838076fa341a83d007fc2fa50957', '0xddee242662323a3cff3f9aa139ffa496ac3c73b0',...]
```

If flatten==False, then you will get a dictionnary in the format below. Keep in mind that created1 may also be a creator somewhere else in the dictionnary.

```Python
{creator:[created1,created2,created3,...]}
#Example:
{'0xd1c24f50d05946b3fabefbae3cd0a7e9938c63f2': ['0xa087b7351c24082ac7ef7ca79b4f4c5d2e82be84', '0x2157a7894439191e520825fe9399ab8655e0f708', '0xc0a47dfe034b400b47bdad5fecda2621de6c4d95'],...}
```

Here are some code examples:


```Python
from Architect import Arch

arch=Arch()

architecture=arch.getArch("0xc0a47dFe034B400B47bDaD5FecDa2621de6c4d95",50,False)

architecture=arch.getArch("0xc0a47dFe034B400B47bDaD5FecDa2621de6c4d95",50,True)

uarch=arch.uniqueContracts(architecture,{})
#returns a dictionary of {address: hash of opcode stack} using every address in the creationdict (unflattened architecture)

highest=arch.getHighest(architecture)
#returns the highest position creator in the creationdict (unflattened architecture)
```
