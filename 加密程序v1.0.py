from cryptography.hazmat.primitives.asymmetric import mlkem,mldsa
from pathvalidate import is_valid_filename
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSAMuHasher
from cryptography.exceptions import InvalidTag,InvalidSignature,UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM,ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher,  modes,algorithms
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.cobblestone import Cobblestone256Decryptor, Cobblestone256Encryptor
from time import sleep,time
import math
from fractions import Fraction
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from hashlib import sha3_512 as sha3
import os
import secrets
from PyQt6 import QtCore, QtGui, QtWidgets,uic
from PyQt6.QtWidgets import QInputDialog
from PyQt6.QtWidgets import QApplication, QLabel, QLineEdit, QPushButton, QFileDialog,QMessageBox,QWidget,QVBoxLayout
import sys
from pqcrypto.sign.slh_dsa_shake_256f import keygen as get_sign_key
from pqcrypto.kem.mceliece_8192128 import decaps as decrypt
from pqcrypto.kem.mceliece_8192128 import keygen as generate_keypair
from pqcrypto.kem.mceliece_8192128 import encaps as encrypt
import pqcrypto
from pqcrypto.sign.slh_dsa_shake_256f import  sign, verify

import tempfile

fenkuai=24*1024*1024  #建议小于16gb

class _hash:
    def update(self,a):
        pass


class xor_en:
    def __init__(self,key,iv):
    
        self.cipher=Cipher(algorithms.AES256(key),mode=modes.CBC(iv[:16])).encryptor()
        
    def update(self,m):
        k=len(m)%16
        if k==0:
            return self.cipher.update(m)
        else:
            return self.cipher.update(m[:len(m)-k])+m[len(m)-k:]

class xor_dn:
    def __init__(self,key,iv):
        self.cipher=Cipher(algorithms.AES256(key),mode=modes.CBC(iv[:16])).decryptor()
    def update(self,m):
        k=len(m)%16
        if k==0:
            return self.cipher.update(m)
        else:
            return self.cipher.update(m[:len(m)-k])+m[len(m)-k:]
class zs:
    def __init__(self,key1,key2,key3,k1,k2,k3,hasher):
        self.hasher=hasher
        self.key1=(int.from_bytes(key1)^int.from_bytes(k1)).to_bytes(32)
        self.key2=(int.from_bytes(key2)^int.from_bytes(k2)).to_bytes(32)
        nonce=(int.from_bytes(key3)^int.from_bytes(k3)).to_bytes(32)
        self.nonce1=nonce[:12]
        self.nonce2=nonce[12:24]
        self.aes=AESGCM(self.key1)
        self.cha=ChaCha20Poly1305(self.key2)
        self.xor=xor_en(nonce,key3)
        self.len=0

    def update(self,m):
        self.len+=1
        self.hasher.update(m)
        self.nonce1=((int.from_bytes(self.nonce1)+1)%(2**(12*8))).to_bytes(12)
        self.nonce2=((int.from_bytes(self.nonce2)+1)%(2**(12*8))).to_bytes(12)
        return self.xor.update(self.cha.encrypt(self.nonce2,self.aes.encrypt(self.nonce1,m,self.len.to_bytes(12)),self.len.to_bytes(12)))


class zs_:
    def __init__(self,key1,key2,key3,k1,k2,k3,hasher):
        self.hasher=hasher
        self.key1=(int.from_bytes(key1)^int.from_bytes(k1)).to_bytes(32)
        self.key2=(int.from_bytes(key2)^int.from_bytes(k2)).to_bytes(32)
        nonce=(int.from_bytes(key3)^int.from_bytes(k3)).to_bytes(32)
        self.nonce1=nonce[:12]
        self.nonce2=nonce[12:24]
        self.aes=AESGCM(self.key1)
        self.cha=ChaCha20Poly1305(self.key2)
        self.xor=xor_dn(nonce,key3)
        self.len=0
        
    def update(self,m):
        self.len+=1
        self.nonce1=((int.from_bytes(self.nonce1)+1)%(2**(12*8))).to_bytes(12)
        self.nonce2=((int.from_bytes(self.nonce2)+1)%(2**(12*8))).to_bytes(12)
        a=self.aes.decrypt(self.nonce1,self.cha.decrypt(self.nonce2,self.xor.update(m),self.len.to_bytes(12)),self.len.to_bytes(12))
        self.hasher.update(a)
        return a



class hasher_maker:
    def __init__(self,a,copy=False):
        if copy:
            return
        else:
            self.hash1=MLDSAMuHasher(a)
            self.hash2=sha3(a.public_bytes_raw())
    def update(self,m):
        self.hash1.update(m)
        self.hash2.update(m)
    def digest(self):
        return self.hash1.finalize(),self.hash2.digest()
    def copy(self):
        hash1=self.hash1.copy()
        hash2=self.hash2.copy()
        a=hasher_maker(None,copy=True)
        a.hash1=hash1
        a.hash2=hash2
        return a
class _:
    def result(self):
        return None

def encrypt_(a):
    b,c=encrypt(a)
    return c,b
#       ------------------加密代码 ------------------
class passwordError(Exception):
    pass
tianchongfn=1100

def dusi_jia(f):
    if os.path.getsize(f.name)==14344:
        a=f.read(32)
        b=f.read(128)
        return a,b
    if os.path.getsize(f.name)==14464:
        s=f.read()
        tis="私钥已加密，请输入密码："
        while True:
            password, ok = QInputDialog.getText(None,"密码验证", tis, QLineEdit.EchoMode.Password)
            if not ok:
                raise passwordError
            try:
                kdf = Argon2id(salt=s[:32],length=32+32+12,iterations=4,lanes=4,memory_cost=512 * 1024,ad=None,secret=None)
                key = kdf.derive(password.encode())
                m=wdjm_(key,s[32:],s[:32])
                return m[:32],m[32:32+128]
            except InvalidTag:
                tis="密码错误，请重新输入："
    raise ValueError
def jiami(path,name):
    suiji=1024*1024*3
    
    changdu=secrets.randbelow(suiji).to_bytes(4)
    
    
    f_gong = open(name + '——公钥', 'rb')
    g=f_gong.read()
    try:
        public_key = mlkem.MLKEM1024PublicKey.from_public_bytes(g[2592+64:64+1568+2592])
    except UnsupportedAlgorithm,ValueError:
        f_gong.close()
        return 4
    pk=g[1568+2592+64:]
    f_gong.close()
    f_s=open(name + '——私钥', 'rb')
    a,b=dusi_jia(f_s)
    try:
        private_key_sign=mldsa.MLDSA87PrivateKey.from_seed_bytes(a)
    except UnsupportedAlgorithm,ValueError:
        f_s.close()
        return 4
    si_sign=b
    f_s.close()

    hasher_=hasher_maker(private_key_sign.public_key())
    key1,c1= public_key.encapsulate()

    hasher_.update(key1)
    key2,c2=public_key.encapsulate()

    hasher_.update(key2)
    key3,c3=public_key.encapsulate()

    hasher_.update(key3)
    k1,c_1=encrypt_(pk)

    hasher_.update(k1)
    k2,c_2=encrypt_(pk)

    hasher_.update(k2)
    k3,c_3=encrypt_(pk)

    hasher_.update(k3)
    
    filename = Path(path).name.encode()
    cipher = zs(key1,key2,key3,k1,k2,k3,hasher_.copy())
    hasher_.update(filename)
    class file:
        def __init__(self, f, long):
            self.f = open(f, 'rb')
            self.long = long
            self.len = math.ceil(Fraction(os.path.getsize(f) , long))
        def read(self):
            return self.f.read(self.long)

    def write(f, msg):
        f.write(msg)

    
    f = file(path,fenkuai) 
    f_ = open('文件——密文', 'wb')
    f_.write('这是一个加密文件，特征码q9ouhg3qi8oa8rgy09w8pg56emxowzrhjytq88w9oertuh0dce5i9'.encode())
    f_.write(c1+c2+c3+c_1+c_2+c_3)
    hasher_.update(changdu)
    long = len(filename)+32
    long=long.to_bytes(2)
    hasher_.update(long)
    r=os.urandom(tianchongfn-int.from_bytes(long))
    hasher_.update(r)
    mu=hasher_.digest()
    signature = private_key_sign.sign_mu(mu[0])
    f_.write(signature+sign(si_sign,mu[1]))


    f_.write(cipher.update(long))
    filename_en=cipher.update(filename)
    f_.write(filename_en)

    f_.write(r)
    f_.write(cipher.update(changdu))

    

    if f.len >= 3:
        with ThreadPoolExecutor(max_workers=3) as pool:
            du = pool.submit(f.read)
            du_jieguo = du.result()
            du = pool.submit(f.read)
            jiami = pool.submit(cipher.update, du_jieguo)
            xie = _()
            for i in range(f.len - 2):
                du_jieguo = du.result()
                du = pool.submit(f.read)
                jiamijieguo = jiami.result()
                jiami = pool.submit(cipher.update, du_jieguo)
                xie.result()
                xie = pool.submit(write, f_, jiamijieguo)

            du_jieguo = du.result()
            jiamijieguo = jiami.result()
            jiami = pool.submit(cipher.update, du_jieguo)
            xie.result()
            xie = pool.submit(write, f_, jiamijieguo)
            jiamijieguo = jiami.result()
            xie.result()
            xie = pool.submit(write, f_, jiamijieguo)
            xie.result()
    else:  # 文件大小太小，不用线程加速
        for i in range(f.len):
            f_.write(cipher.update(f.read()))

    f_.write(os.urandom(int.from_bytes(changdu)))
    zhaiyao=cipher.hasher.digest()

    signature = private_key_sign.sign_mu(zhaiyao[0])
    f_.write(signature)
    signature = sign(si_sign,zhaiyao[1])
    f_.write(signature)
    f_.close()
    return 1

#       ------------------解密代码 ------------------
def miwen():
    try:
        open('文件——密文', 'rb').close()
        return  None    
    except FileNotFoundError:
        return False


def jiemi(f_,key1,key2,key3,k1,k2,k3,public_key_sign,g_sign):

    f = open('文件——密文', 'rb')
    a=f.read(89)
    if a!='这是一个加密文件，特征码q9ouhg3qi8oa8rgy09w8pg56emxowzrhjytq88w9oertuh0dce5i9'.encode():
        raise
    f.seek(f.tell()+1568*3+208*3,0)
    text=f.read(4627)
    te=f.read(49856)
    hasher_=hasher_maker(public_key_sign)
    
    
    class file_decrypt:
        def __init__(self, f, long,c):
            self.f = f
            self.long = long+32
            self.size=os.path.getsize(f.name) - f.tell()-c-49856-4627
            self.len = math.ceil(Fraction(self.size, self.long))
            

        def read(self):
            if self.size>=self.long:
                self.size-=self.long
                return self.f.read(self.long)
            else:
                return self.f.read(self.size)

    def write(file,data):
        file.write(data)



    hasher_.update(key1)
    hasher_.update(key2)
    hasher_.update(key3)
    hasher_.update(k1)
    hasher_.update(k2)
    hasher_.update(k3)

    cipher = zs_(key1,key2,key3,k1,k2,k3,hasher_.copy())
    fnl=f.read(2+32)
    fnl=cipher.update(fnl)


    fn = f.read(int.from_bytes(fnl))
    fn=cipher.update(fn)
    r=f.read(tianchongfn-int.from_bytes(fnl))
    if not is_valid_filename(fn.decode()):
        f.close()
        return 2

    changdu=f.read(4+32)

    hasher_.update(fn)
    changdu=cipher.update(changdu)
    hasher_.update(changdu)
    hasher_.update(fnl)
    hasher_.update(r)
    public_key_sign.verify_mu(text,hasher_.digest()[0])
    changdu=int.from_bytes(changdu)
    f = file_decrypt(f, fenkuai,changdu)  
    
    if f.len >= 3:

        with ThreadPoolExecutor(max_workers=3) as pool:
            du = pool.submit(f.read)
            du_jieguo = du.result()
            du = pool.submit(f.read)
            jiami = pool.submit(cipher.update, du_jieguo)
            xie = _()
            for i in range(f.len - 2):
                du_jieguo = du.result()
                du = pool.submit(f.read)
                jiamijieguo = jiami.result()
                jiami = pool.submit(cipher.update, du_jieguo)
                xie.result()
                xie = pool.submit(write,f_, jiamijieguo)

            du_jieguo = du.result()
            jiamijieguo = jiami.result()
            jiami = pool.submit(cipher.update, du_jieguo)
            xie.result()
            xie = pool.submit(write,f_, jiamijieguo)
            jiamijieguo = jiami.result()
            xie.result()
            xie = pool.submit(write,f_, jiamijieguo)
            xie.result()


    else:
        for i in range(f.len):
            write(f_,cipher.update(f.read()))
    f.f.seek(f.f.tell()+changdu)
    t=cipher.hasher.digest()
    try:
        public_key_sign.verify_mu(f.f.read(4627),t[0])
    except InvalidSignature:
        f_.close()
        os.remove(f_.name)
        raise 
    try:
        verify(g_sign, t[1], f.f.read(49856))
    except pqcrypto.InvalidSignatureError:
        f_.close()
        os.remove(f_.name)
        raise InvalidSignature

    f_.close()
    os.replace(f_.name,fn.decode())
    return 1


def dusi_jie(f):
    if os.path.getsize(f.name)==14344:

        return f.read()
    if os.path.getsize(f.name)==14464:
        s=f.read()
        tis="私钥已加密，请输入密码："
        while True:
            password, ok = QInputDialog.getText(None,"密码验证", tis, QLineEdit.EchoMode.Password)
            if not ok:
                raise passwordError
            try:
                kdf = Argon2id(salt=s[:32],length=32+32+12,iterations=4,lanes=4,memory_cost=512 * 1024,ad=None,secret=None)
                key = kdf.derive(password.encode())
                m=wdjm_(key,s[32:],s[:32])
                return m
            except InvalidTag:
                tis="密码错误，请重新输入："
    raise ValueError

def line(name):
    global line_1
    f = open('文件——密文', 'rb')
    a=f.read(89)
    if a!='这是一个加密文件，特征码q9ouhg3qi8oa8rgy09w8pg56emxowzrhjytq88w9oertuh0dce5i9'.encode():
        return 2
    c1 = f.read(1568)
    c2 = f.read(1568)
    c3=f.read(1568)
    c_1=f.read(208)
    c_2=f.read(208)
    c_3=f.read(208)
    text=f.read(4627)
    te=f.read(49856)
    f_s = open(name + '——私钥', 'rb')
    seed = dusi_jie(f_s)
    f_s.close()
    try:
        private_key = mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed[32+128:96+128])
    except UnsupportedAlgorithm,ValueError:
            
            return 4
    pk=seed[96+128:]
    f_s.close()
    f_g=open(name + '——公钥', 'rb')
    try:
        public_key_sign=mldsa.MLDSA87PublicKey.from_public_bytes(f_g.read(2592))
    except UnsupportedAlgorithm,ValueError:
            f_g.close()
            return 4
    g_sign=f_g.read(64)
    f_g.close()
    hasher_=hasher_maker(public_key_sign)
    fnl=f.read(2+32)


    key1=private_key.decapsulate(c1)
    key2=private_key.decapsulate(c2)
    key3=private_key.decapsulate(c3)
    k1=decrypt(pk,c_1)
    k2=decrypt(pk,c_2)
    k3=decrypt(pk,c_3)

    hasher_.update(key1)
    hasher_.update(key2)
    hasher_.update(key3)
    hasher_.update(k1)
    hasher_.update(k2)
    hasher_.update(k3)

    cipher = zs_(key1,key2,key3,k1,k2,k3,_hash())
    
    fnl=cipher.update(fnl)

    fn = f.read(int.from_bytes(fnl))
    fn=cipher.update(fn)
    r=f.read(tianchongfn-int.from_bytes(fnl))

    changdu=f.read(4+32)
    hasher_.update(fn)
    changdu=cipher.update(changdu)
    hasher_.update(changdu)
    hasher_.update(fnl)
    hasher_.update(r)
    t=hasher_.digest()
    try:
        public_key_sign.verify_mu(text,t[0])
    except InvalidSignature:
        return 3
    try:
        verify(g_sign, t[1], te)
    except pqcrypto.InvalidSignatureError:
        return 3
    line_1 =fn.decode()
    return key1,key2,key3,k1,k2,k3,public_key_sign,g_sign

    #       ------------------生成密钥代码 ------------------

def shengcheng(name):

    if os.path.exists(name+'——私钥'):
        return 3                #有重名回3
    if os.path.exists(name+'——公钥'):
        return 3
    private_key = mlkem.MLKEM1024PrivateKey.generate()
    sleep(0.1)#等待系统加熵
    public_key=private_key.public_key()
    private_key_sign = mldsa.MLDSA87PrivateKey.generate()
    sleep(0.1)
    public_key_sign=private_key_sign.public_key()
    pk, sk = generate_keypair()
    sleep(0.1)
    pk_sign, sk_sign = get_sign_key()#64,128
    
    s=private_key_sign.private_bytes_raw()+sk_sign+private_key.private_bytes_raw()+sk
    
    with open(name+'——公钥','wb')as f:
        f.write(public_key_sign.public_bytes_raw()+pk_sign+public_key.public_bytes_raw()+pk)
    
    return 1,s







def wdjm_(key,s,salt):
    k=Cobblestone256Decryptor(key[:32],salt)
    m=k.update(s)
    m+=k.finalize()

    k=ChaCha20Poly1305(key[32:32+32])
    return k.decrypt(key[32+32:32+32+12],m,salt)


def wdjm(key,m,salt):
    k=ChaCha20Poly1305(key[32:32+32])
    s=k.encrypt(key[32+32:32+32+12],m,salt)

    k=Cobblestone256Encryptor(key[:32],salt)
    s=k.update(s)
    s+=k.finalize()
    return s
    

def jiamisi(key:str,si):
    key=key.encode()
    salt = os.urandom(32)
    kdf = Argon2id(
    salt=salt,
    length=32+32+12,
    iterations=4,
    lanes=4,
    memory_cost=512 * 1024,
    ad=None,
    secret=None,
    )
    key = kdf.derive(key)

    s=wdjm(key,si,salt)
    return salt+s


    #       ------------------图形化代码 ------------------

def test(a):
    print("a")

def showInfo(a):
    QMessageBox.information(None, '提示', a,QMessageBox.StandardButton.Ok)

def showQuestion(a):
    QMessageBox.information(None, '提示', a,QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)

def showWarm(a):
    QMessageBox.warning(None, '错误', a,QMessageBox.StandardButton.Ok)

fileside = ""
def again_jiami():
    text = lineEdit_2.text().strip()
    if not fileside:
        showWarm("未选择文件")
        return
    if miwen()==None:
        b = QMessageBox.information(None, '提示', "在该程序同目录下有加密文件,是否覆盖？",QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)
        if b== QMessageBox.StandardButton.No:
            showInfo("请自行改变文件名称")
            return
    if os.path.exists(text+'——公钥') == False or os.path.exists(text+'——私钥')==False:
        if not text:
            showWarm("未输入公钥")
            return
        else:
            showWarm("未将公钥或私钥放在与该程序同目录下")
            return 2
    if os.path.exists(text+'——公钥') and os.path.exists(text+'——私钥'):
        pushButton_3.setEnabled(False)
        pushButton_3.repaint()
        QApplication.processEvents()
        result = jiami(fileside,lineEdit_2.text())
        if result == 1:
            showInfo("已成功加密")
            showInfo("已将加密文件放在与该程序同目录下")
            pushButton_3.setEnabled(True)
        if result ==4:
            showWarm("加密失败，请检查密钥和磁盘空间")
            pushButton_3.setEnabled(True)

def again_jiami_():
    try:
        again_jiami()
    except OSError :
        showWarm("文件或硬盘异常，请检查文件权限和硬盘空间")
    except passwordError:
            showWarm("未输入密码，加密失败")
    except Exception :
        showWarm("公钥或私钥无效")

    pushButton_3.setEnabled(True)
def again_jiemi():
    pushButton_4.setEnabled(False)
    text = lineEdit_3.text().strip()
    miwen_1 = miwen()
    if miwen_1 == False:
        showWarm("未将密文放在与该程序同目录下")
        return 
    if os.path.exists(text + '——私钥') == False or os.path.exists(text + '——公钥')==False:
        if not text:
            showWarm("未输入私钥")
        else:
            showWarm("未将私钥或公钥放在与该程序同目录下")
    else:
        pushButton_4.repaint()
        QApplication.processEvents()
        try:
           a=line(lineEdit_3.text())
        except InvalidTag:
            showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因，解密已停止")
            return
        except passwordError:
                showWarm("未输入密码，解密失败")
                return
        except Exception as a:
            showWarm(f"解密失败：{a}")
            return
        if a==2:
            showWarm("文件格式不对")
            return None
        if a==3:
            showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因，解密已停止")
            return
        if a==4:
            showWarm("公钥或私钥无效")
            return None
        if os.path.exists(line_1) == True:
            b = QMessageBox.information(None, '提示', "在该程序同目录下有同名文件是否要覆盖？文件名："+line_1,QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)
            
            if b == QMessageBox.StandardButton.Ok:
                try:
                    with tempfile.NamedTemporaryFile(mode='wb',delete=False,dir='.')as f:
                        name=f.name
                        result = jiemi(f,*a)
                except InvalidSignature:
                    try:
                        os.remove(name)
                    except FileNotFoundError:
                        pass
                    showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因,已写入部分文件，但已删除")
                    return
                except InvalidTag:
                    os.remove(name)
                    showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因,已写入部分文件，但已删除")
                    return
                except Exception as a:
                    os.remove(name)
                    showWarm(f"解密失败：{a}")
                    return
                if  result == 2:
                    os.remove(name)
                    showWarm("文件名不合法，可能是因为系统问题或其他问题")
                if result == 1:
            
                    showInfo("已成功解密")
                    showInfo("已将解密文件放在与该程序同目录下")
            if b == QMessageBox.StandardButton.No:
                
                showInfo("请自行改变文件名称")
        else:
            
            try:
                with tempfile.NamedTemporaryFile(mode='wb',delete=False,dir='.')as f:
                    name=f.name
                    result = jiemi(f,*a)
            except InvalidSignature:
                try:
                    os.remove(name)
                except FileNotFoundError:
                    pass
                showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因,已写入部分文件，但已删除")
                return
            except InvalidTag:
                os.remove(name)
                showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因,已写入部分文件，但已删除")
                return
            except Exception as a:
                os.remove(name)
                showWarm(f"解密失败：{a}")
                return
            if  result == 2:
                os.remove(name)
                showWarm("文件名不合法，可能是因为系统问题或其他问题")
            if result == 1:
                showInfo("已成功解密")
                showInfo("已将解密文件放在与该程序同目录下")
def again_jiemi_():
    pushButton_4.setEnabled(False)
    again_jiemi()
    pushButton_4.setEnabled(True)
def again_shengcheng():
    text = lineEdit.text()
    if not text:
        showWarm("未输入名称")
        return 2
    if os.path.exists(text + '——公钥') == True or os.path.exists(text + '——私钥') == True:
        showWarm("该程序的相同目录下有重名密钥")
        return 2
    else:
        pushButton.setEnabled(False)
        pushButton.repaint()
        QApplication.processEvents()
        result ,si= shengcheng(text)
        if result == 1:
            pushButton.setEnabled(True)
            showInfo("已成功生成密钥")
            a=QMessageBox.information(None, '提示', "是否加密私钥：",QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)

            if a==QMessageBox.StandardButton.Ok:
                while True:
                    password1, ok = QInputDialog.getText(None,"密码验证", "请输入密码：", QLineEdit.EchoMode.Password)
                    if not ok:
                        break
                    password2, ok = QInputDialog.getText(None,"密码验证", "请再次输入密码：", QLineEdit.EchoMode.Password)
                    if not ok:
                        break
                    if password1==password2:
                        si=jiamisi(password1,si)
                        with open(text + '——私钥','wb') as f:
                            f.write(si)
                        return 2
                    showInfo("两次密码输入不同，请重新输入")
            with open(text + '——私钥','wb') as f:
                f.write(si)

                        

def selectFile():
    global fileside
    fd = QFileDialog()
    fd.setFileMode(QFileDialog.FileMode.ExistingFile)  # 设置多选
    fd.setDirectory('C:/')  # 设置初始化路径
    if fd.exec():  # 执行

        fileside = fd.selectedFiles()[0]
        print(fileside)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    try:
        a=os.path.join(sys._MEIPASS,'untitled.ui')
    except AttributeError:
        a='./untitled.ui'
    ui = uic.loadUi(a)    #初始化

    lineEdit: QLineEdit = ui.lineEdit       #输入文本一，生成密钥
    lineEdit_2: QLineEdit = ui.lineEdit_2   #输入文本二，加密
    lineEdit_3: QLineEdit = ui.lineEdit_3

    pushButton: QPushButton = ui.pushButton     #按钮一，生成密钥
    pushButton_2: QPushButton = ui.pushButton_2
    pushButton_3: QPushButton = ui.pushButton_3
    pushButton_4: QPushButton = ui.pushButton_4

    pushButton.clicked.connect(lambda:again_shengcheng())

    pushButton_2.clicked.connect(selectFile)
    pushButton_3.clicked.connect(lambda: again_jiami_())

    pushButton_4.clicked.connect(lambda: again_jiemi_())
    ui.show()

    sys.exit(app.exec())

