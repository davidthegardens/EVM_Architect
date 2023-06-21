import os
import pickle

class KeyManager:
    def __init__(self):
        pass

    def GetExpectedPath(self,KeyName):
        ExpectedDir=os.path.relpath("API_Keys/")
        ExpectedFile=os.path.join(ExpectedDir,KeyName+".pickle")
        IsRegistered=os.path.isfile(ExpectedFile)
        if IsRegistered==False:
            ExpectedExists=os.path.isdir(ExpectedDir)
        else: ExpectedExists=True
        return ExpectedDir,ExpectedFile,IsRegistered,ExpectedExists
    
    def Easy_Key(self,KeyName):
        KeyName=KeyName.lower()
        ExpectedDir,ExpectedFile,IsRegistered,ExpectedExists=KeyManager().GetExpectedPath(KeyName=KeyName)
        if os.path.exists(".gitignore")==False:
            with open(".gitignore","w") as f:
                f.write("#Gitignore added by easykey")
        with open(".gitignore","r") as f:
            lines=f.readlines()
        notin=True
        for line in lines:
            if "API_Keys" in line:
                notin=False
                break
            else:
                notin=True
        if notin==True:
            with open(".gitignore","a") as g:
                    g.write("\nAPI_Keys/")
        if IsRegistered==False:
            if ExpectedExists==False:
                os.makedirs(os.path.abspath(ExpectedDir))
            key=input("Please enter the API key: ")
            with open(ExpectedFile,"wb") as f:
                pickle.dump(key,f)
            return key
        else:
            with open(ExpectedFile,"rb") as f:
                return pickle.load(f)