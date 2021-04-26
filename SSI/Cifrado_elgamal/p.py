import random
from math import pow

#a=random.randint(2,10)
#To fing gcd of two numbers
def gcd(a,b):
    if str(a) < str(b):
        return gcd(b,a)
    elif (a%b)==0:
        return b
    else:
        return gcd(b,a%b)
    
    
#For key generation i.e. large random number
def gen_key(a,x,p):
    key=(pow(int(a),int(x)),p)
    while gcd(p,key)!=1:
        key=(pow(int(a),int(x)),p)
    return key


def mod(a,b,c):
    x=1
    y=a
    while b>0:
        if b%2==0:
            x=(x*y)%c;
        y=(y*y)%c
        b=int(b/2)
    return x%c
#For asymetric encryption
def encryption(msg,q,h,g):
    ct=[]
    k=gen_key(q)
    s=mod(h,k,q)
    p=mod(g,k,q)
    for i in range(0,len(msg)):
        ct.append(msg[i])
    print("g^k used= ",p)
    print("g^ak used= ",s)
    for i in range(0,len(ct)):
        ct[i]=s*ord(ct[i])
    return ct,p
#For decryption
def decryption(ct,p,key,q):
    pt=[]
    h=mod(p,key,q)
    for i in range(0,len(ct)):
        pt.append(chr(int(ct[i]/h)))
    return pt

print("Entrada")
p=input("Introduce p o numero primo: ")
a=input("Introduce a o numero entero: ")
k=input("Introduce el secreto k (Alice): ")
x=input("Introduce el secreto x (Bob): ")
msg=input("Introduce m o mensaje a cifrar: ")

print("Entrada: ")
print("p = ",p)
print("a = ",a)
print("k = ",k)
print("x = ",x)
print("m = ",msg)

key=gen_key(a,x,p)
K=mod(a,key,p)

#q=random.randint(pow(10,20),pow(10,50))
#g=random.randint(2,q)
#key=gen_key(q) #lo que computa
#h=power(g,key,q)  #clave publica
print("g used=",p)
print("g^a used=",K)
ct,po=encryption(msg,p,K,a)
print("Original Message=",msg)
print("Encrypted Maessage=",ct)
pt=decryption(ct,po,key,p)
d_msg=''.join(pt)
print("Decryted Message=",d_msg)