from tkinter import *
from tkinter.ttk import *

from tkinter.filedialog import askopenfile

root = Tk()
root.geometry('200x100')
root = Tk()

def open_file():
	file = askopenfile(mode ='r', filetypes =[('Python Files', '*.csv')])
	if file is not None:
		content = file.read()
		print(content)

btn = Button(root, text ='Upload File  ', command = lambda:open_file())
btn.pack(side = TOP, pady = 10)
Button(root, text="Quit", command=root.destroy).pack()
root.mainloop()


import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from tinyec import registry
import secrets
from Crypto.Cipher import AES
import hashlib, binascii
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')
from sklearn.cluster import KMeans
from sklearn import metrics

#---------------------------------------------------------------------------
"Load a dataset"
print("DATASET LOADED SUCESSFULLY....")
df=pd.read_csv('Cybersecuritydataset.csv')

#----------------------------------------------------------------------------

print("CHECKING ANY VALUE ARE MISSING IN DATASET")
df.isnull().sum()

#--------------------------------------------------------------------------
len(df)
nRow, nCol = df.shape
print(f'There are {nRow} rows and {nCol} columns')
#-----------------------------------------------------------------------

print(f"Duplicated rows: {df.duplicated().sum()}")

#---------------------------------------------------------------------------
"ECC Based Novel Diffie Hellman Encryption"

curve = registry.get_curve('brainpoolP256r1')

def compression(point):
    return hex(point.x) + hex(point.y % 2)[2:]

def cal_keys_for_encrypt(pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = pubKey * ciphertextPrivKey
    return (sharedECCKey, ciphertextPubKey)

def cal_keys_for_decrypt(privKey, ciphertextPubKey):
    sharedECCKey = ciphertextPubKey * privKey
    return sharedECCKey

privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

print("\n")
print("Generated Keys...")
print("Private Key:", hex(privKey))
print("Public Key:", compression(pubKey))

(encryptKey, ciphertextPubKey) = cal_keys_for_encrypt(pubKey)
print("Ciphertext PubKey:", compression(ciphertextPubKey))
print("Encryption Key:", compression(encryptKey))

decryptKey = cal_keys_for_decrypt(privKey, ciphertextPubKey)
print("Decryption Key:", compression(decryptKey))

print("\n")

def AES_Encryption(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def AES_Decryption(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ECC_bit_key_generation(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def ECC_Encryption(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ECC_bit_key_generation(sharedECCKey)
    ciphertext, nonce, authTag = AES_Encryption(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

column_names = list(df.columns)

result = df.values

print("Encrypting  CSV file...")  
empty = []
#empty_decoded = []
for i in result:
    for j in i:
        a = str(j)
        en = a.encode()
        s = ECC_Encryption(en, pubKey)
        b = binascii.hexlify(s[0])
        encoded_text = b.decode('utf-8')
        empty.append(encoded_text)
        #print(f"Encoded Text : {encoded_text}")
 #-------------------------------------------------------------------------------------       
def ECC_Decryption(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ECC_bit_key_generation(sharedECCKey)
    plaintext = AES_Decryption(ciphertext, nonce, authTag, secretKey)
    return plaintext

print(" Decrypting the CSV file...")  
empty_decoded = []
for i in result:
    for j in i:
        a = str(j)
        en = a.encode()
        s = ECC_Encryption(en, pubKey)       
        de = ECC_Decryption(s, privKey)
        decoded_text = de.decode('utf-8')
        empty_decoded.append(decoded_text)
        #print(f"Decoded Text  : {decoded_text}")
#---------------------------------------------------------------------------------------------
encrypted_df = pd.DataFrame(np.array(empty).reshape(149,4),columns = column_names)
decrypted_df = pd.DataFrame(np.array(empty_decoded).reshape(149,4),columns = column_names) 

print("Encryption Completed and written as encryption.csv file")
encrypted_df.to_csv(r'encrypted.csv',index = False)

print("Decryption Completed and written as decryption.csv file")
decrypted_df.to_csv(r'decrypted.csv',index = False)

#-----------------------------------------------------------------------------------------

from easygui import *
task = "Enter the Admin Login  number to be Search"
text_query = "Enter the Query to be Search"

Key = "Enter the Key to be Search"
  
# window title
title = "Query"
task1 = enterbox(task, title)
  
# creating a integer box
str_to_search1 = enterbox(text_query, title)

Key = passwordbox(Key, title)



if task1 in ["163052"]:
    print("Reterival Cybersecurity ")
    global data1   
    data = pd.read_csv("C:/Users/egc/CloudMe/cybersecuritydataset/Cybersecuritydataset.csv")
    if (Key=='Cybersecurity'):    
        print("Correct Key")
        data1=data[data['Keyword'].str.contains(str_to_search1)]
        
        print(data1)    
    else:
        print("Incorrect Key")

