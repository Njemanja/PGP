from tkinter import  *
from tkinter import messagebox
import rsa
import datetime

class PrivateRingField:
    def __init__(self, name, email, publicKey, privateKey):
        self.name = name
        self.email = email
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.timestamp = datetime.datetime.now()
       # self.keyID = publicKey % 2^64
        self.userID = name + email



PrivateKeyRing = {}

root=Tk()
root.title=("Zastita podataka")
root.geometry("1200x500")



#Podaci
nameVar = StringVar()
emailVar = StringVar()
Label(root,text = "Unesite podatke",  font=("Arial", 20)).place(x = 40,y = 10)
ime1 = Label(root,text = "Ime",   font=("Arial", 13)).place(x = 40,y = 60)
email1 = Label(root,text="Email",  font=("Arial", 13)).place(x=40,y=100)
ime = Entry(root,textvariable=nameVar,width=30)
ime.place(x=110,y=60)
email = Entry(root,textvariable=emailVar,width=30)
email.place(x=110,y=100)

#Algoritmi
r= IntVar()
k= IntVar()
Label(root,text = "Izaberite algoritam", font=("Arial", 20)).place(x = 500,y = 10)
Radiobutton(root, text="RSA", variable=r  ,value=1,  font=("Arial", 13)).place(x = 500,y = 50)
Radiobutton(root, text="Drugi algoritam", variable=r ,value=2,  font=("Arial", 13)).place(x = 500,y = 80)
Radiobutton(root, text="Treci algoritam",variable=r ,value=3,  font=("Arial", 13)).place(x = 500,y = 110)
Radiobutton(root, text="Cetvrti algoritam",variable=r ,value=4,  font=("Arial", 13)).place(x = 500,y = 140)
#VelicinaKljuca
Label(root,text = "Izaberite velicinu kljuca", font=("Arial", 20)).place(x = 800,y = 10)
Radiobutton(root, text="1024",variable=k ,value=1024,  font=("Arial", 13)).place(x = 800,y = 50)
Radiobutton(root, text="2048",variable=k ,value=2048, font=("Arial", 13)).place(x = 800,y = 80)
#Lozinka
lozinka1 = Label(root,text="Lozinka",  font=("Arial", 20)).place(x=40,y=200)
lozinka = Entry(root,width=30, show="*")
lozinka.place(x=40,y=250)
#Poruka
global poruka
poruka=Label(root,text="",  font=("Arial", 13))
poruka.place(x=500,y=350)

def potvrdi():
   global poruka
   '''
   if(ime.get()==None or email.get()==None or r.get()==0 or k.get()==0 or lozinka.get()==None):
       poruka=Label(root,text="Niste uneli sve podatke!",  font=("Arial", 13))
       poruka.place(x=500,y=350)
   else:
       poruka.destroy()
       #Nastavak
    '''
   if r.get() == 1: # rsa
       messagebox.showinfo("info", "rsa")
       generateKeysRSA(k.get())
       e, d = loadKeysRSA()
       ringItem = PrivateRingField(nameVar.get(),emailVar.get(), e, d)
       if ringItem.userID not in PrivateKeyRing:
           PrivateKeyRing[ringItem.userID] = [ringItem]
       else:
           PrivateKeyRing[ringItem.userID].append(ringItem)
       #test
       mojaPoruka = "rsa encryption test"
       cipherPoruka = encrypt(mojaPoruka, e)
       messagebox.showinfo("cipher", cipherPoruka)
       desifrovanaPoruka = decrypt(cipherPoruka, d)
       messagebox.showinfo("M", desifrovanaPoruka)



def generateKeysRSA(size):
    (publicKey, privateKey) = rsa.newkeys(size)
    with open('userA/publicKeys.pem', 'wb') as f:
        f.write(publicKey.save_pkcs1('PEM'))
    with open('userA/privateKeys.pem', 'wb') as f:
        f.write(privateKey.save_pkcs1('PEM'))

def loadKeysRSA():
    with open('userA/publicKeys.pem', 'rb') as f:
        publicKey = rsa.PublicKey.load_pkcs1(f.read())
    with open('userA/privateKeys.pem', 'rb') as f:
        privateKey = rsa.PrivateKey.load_pkcs1(f.read())
    return publicKey, privateKey

def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False

def sign(message, key):
    return rsa.sign(message.encode('ascii'), key, 'SHA-1')

def verify(message, signature, key):
    try:
        return rsa.verify(message.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return false


potvrdi = Button(root,text="Potvrdi",  font=("Arial", 13), command=potvrdi).place(x=500,y=300)
root.mainloop()

