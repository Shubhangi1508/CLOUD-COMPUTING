import tkinter
import tkinter.messagebox
import sqlite3
from tkinter import * 
import tkinter as tk
from random import *
import string


entry_1 = None;
entry_2 = None;
entry_3 = None;

class ForFrames(tk.Tk):
    
     def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        container = tk.Frame(self)  
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)


        self.frames = {}
        for F in (Registerform,Login):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame


            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("Registerform")

     def show_frame(self, page_name):

        frame = self.frames[page_name]
        frame.tkraise() 

class Registerform(tk.Frame):
    def __init__(self,parent,controller):

        tk.Frame.__init__(self, parent)
        self.controller = controller




            # convert registered userinfo to json file
        def regPress():
            usern = entry_1.get()
            passw = entry_2.get()
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            if entry_2.get() == entry_3.get() and not len(entry_1.get()) == 0:
                c.execute("CREATE TABLE IF NOT EXISTS 'entries' (username TEXT, password TEXT)")
                c.execute("INSERT INTO entries(username,password)VALUES(?,?)",(usern,passw))
                MsgBox = tkinter.messagebox.showinfo("Success","Registered, click OK to login")
                if MsgBox == 'ok':
                    controller.show_frame("Login")
            conn.commit()
            
            if entry_2.get() != entry_3.get():
                     tkinter.messagebox.showinfo("Failed","Passwords don't match")
            elif len(entry_1.get()) == 0:
                    tkinter.messagebox.showinfo("Failed","Please enter a username")

     

                
        registerframe1 = Frame(self)
        registerframe1.pack(fill=X)

        registerframe2 = Frame(self)
        registerframe2.pack(fill=X)

        registerframe3 = Frame(self)
        registerframe3.pack(fill=X)

        registerframe6 = Frame(self)
        registerframe6.pack(fill=X)

        label_1 = tk.Label(registerframe1, text="Username")
        label_2 = tk.Label(registerframe2, text="Password")
        label_3 = tk.Label(registerframe3, text="Password confirmation")
        

        label_1.pack(side=LEFT,padx=5,pady=5)
        label_2.pack(side=LEFT,padx=5,pady=5)
        label_3.pack(side=LEFT,padx=5,pady=5)
        

        entry_1 = Entry(registerframe1, width=50)
        entry_2 = Entry(registerframe2, width=50, show='*')
        entry_3 = Entry(registerframe3, width=50, show='*')

        entry_1.pack(side=RIGHT,padx=100)
        entry_2.pack(side=RIGHT,padx=100)
        entry_3.pack(side=RIGHT,padx=100)
        
        

         

        def randompw():
            
                characters = string.ascii_letters + string.digits
                pwmessage = "".join(choice(characters) for x in range (randint(8, 12)))
                print (pwmessage)

                

                registerframePW = Frame(self)
                registerframePW.pack(fill=X)

                label_PW = tk.Label(registerframePW, text="This is your password. Please, never share it !")
                label_PW.pack()

                entryText = tk.StringVar()
                entry_PW = Entry(registerframePW, width=50, textvariable=entryText)
                entryText.set(pwmessage)
                entry_PW.pack()

            
            
            
            
              
        #### nupud



        button1 = tk.Button(self, text="Register", command=regPress)
        button2 = tk.Button(self, text="Already have an account? Login",command=lambda: controller.show_frame("Login"))
        button3 = tk.Button(self, text="Create a random password",command=randompw)

        
        button2.pack(side=BOTTOM)
        button1.pack(side=TOP,padx=5,pady=5)
        button3.pack(side=BOTTOM)
         


        

class Login(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        self.controller = controller

        #database
        def LogPress():
            usern = entry_1.get()
            passw = entry_2.get()
            if usern == '' or passw == '':
                tkinter.messagebox.showinfo("Failed","Please enter username and password")

            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("SELECT * FROM entries WHERE username = ? and password = ?",(usern,passw))
            if c.fetchall():
                tkinter.messagebox.showinfo(title = "Successfully logged in", message = "Welcome!!! ")
            else:
                tkinter.messagebox.showerror(title = "Error", message = "incorrect username or password")

            c.close()   


        registerframe4 = Frame(self)
        registerframe4.pack(fill=X)

        registerframe5 = Frame(self)
        registerframe5.pack(fill=X)

        label_1 = tk.Label(registerframe4, text="Username")
        label_2 = tk.Label(registerframe5, text="Password")

        label_1.pack(side=LEFT,padx=5,pady=5)
        label_2.pack(side=LEFT,padx=5,pady=5)

        entry_1 = Entry(registerframe4, width=50)
        entry_2 = Entry(registerframe5, width=50, show='*')

        entry_1.pack(side=RIGHT,padx=100)
        entry_2.pack(side=RIGHT,padx=100)

        button1 = tk.Button(self, text="Login",command=LogPress)
        button1.pack(side=TOP)
        button2 = tk.Button(self, text="Don't have an account?", command=lambda: controller.show_frame("Registerform"))
        button2.pack(side=BOTTOM)

        
       
            

    def close_window(self):
        self.master.destroy()


if __name__ == "__main__":


    app = ForFrames()
    app.geometry("700x250")
    app.mainloop()
    
    
    
 #-----------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
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
df=pd.read_csv('dataset.csv')

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
"ECC Based AES"

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

print("Encrypting  CSV file Save from Cloud ...")  
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

print(" Decrypting the CSV file Save from Cloud...")  
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

task = "Enter the Admin password "
text_query = "Enter the Query to be Search"

Key = "Enter the Key to be Search"
  
# window title
title = "Query"
task1 = enterbox(task, title)
  
# creating a integer box
str_to_search1 = enterbox(text_query, title)

Key = passwordbox(Key, title)



if task1 in ["165"]:
    print("Reterival Cybersecurity ")
    global data1   
    data = pd.read_csv("dataset.csv")
    if (Key=='Shubhangi'):    
        print("Correct Key")
        data1=data[data['Keyword'].str.contains(str_to_search1)]
        
        print(data1)    
    else:
        print("Incorrect Key")

   
    
    
