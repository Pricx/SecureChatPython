#coding:utf-8
import threading
import time
import sys
from Crypto import Random
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA3_256
from Crypto.Util.Padding import pad,unpad
from Crypto.Signature import DSS
from base64 import b64encode as b64e
from base64 import b64decode as b64d
from Crypto.Cipher import AES
import json
import signal

from socket import *

SERVERIP = "xx.xx.xx.xx"
SERVERPORT = 8888
MASTER_PASS = "dhwoahuhrwahdwdwadwadwadwad"
TIME_SYNC_INTERREGNUM = 30# less than 99
CIPHER_ID = "DATA:"
MSG_ID = "CHATTING_MSG:"
ECC_CURVE_TYPE = 'P-256'
FIRST = 0
INIT_TIME_STAMP = 0
IS_EXIT = False

def info(x):
    print("[*] "+str(x))
def warn(x):
    print("[!] "+str(x))
def success(x):
    print("[Y] "+str(x))

def EXIT():
    global clientSocket
    clientSocket.close()
    exit()

def handler(signum, frame):
    global IS_EXIT,clientSocket
    IS_EXIT = True
    clientSocket.close()
    print ("receive a signal %d, is_exit = %d"%(signum, IS_EXIT))

def to_integer(dt_time): 
    return 10000*dt_time.year + 100*dt_time.month + dt_time.day 



def f_sGetKey():
    h_obj = SHA3_256.new()
    key=(str(int(time.time())//100)+MASTER_PASS)
    h_obj.update(key)
    key = h_obj.hexdigest()[:32]
    info("AES key: "+key)
def f_sECBEncryptAndB64e(key,s):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(s, AES.block_size))
    ciphertext = b64e(ciphertext)
    return ciphertext
def f_sECBDecryptAndB64d(key,s):
    plain = AES.new(key, AES.MODE_ECB)
    ct = b64d(s)
    recMessage = unpad(plain.decrypt(ct), AES.block_size)
    return recMessage
def f_sSHA256And32bytes(s):
    h_obj = SHA3_256.new()
    h_obj.update(str(s)+MASTER_PASS)
    val = h_obj.hexdigest()[:32]
    return val
def f_sSHA256(s):
    h_obj = SHA3_256.new()
    h_obj.update(str(s)+MASTER_PASS)
    return h_obj.hexdigest()

def f_lKeyExchange():
    '''
    ## 用法
        - ECDH_Key,MyKey,FriendKey = f_lKeyExchange()
    ## 返回值
        - 32bytes的整数 256位
    ## 效果
    [+] Connected to 192.168.43.143
    [*] Friend Timestamp: 1608726043.14
    [+] P2P success
    [*] AES key: 07123f4f28e91bf32b0c1c07170c8ebf
    [*] Ciphertext(send): S7iUb3ANbK+COE85TnEp8PDeIdkUgayJ3Qhc8t5Pc30saMUosvntFESnPqPBuXYbETQ96rwlsWg6YUlMxwzYiex4HKrP9y3K5J1J8a8oSghJsCocjfu+KN1B7wJ1/6wWbbvi/N2yGaAMvhHIjSpONQDoTZDnUw3T8Rx+t5k4Ab154hOPPIetmSFdXdRrXOemuAQgxvXxkDhbrOPb1SQzV1+FmKdXKYQe2gRsPULvc14=
    [*] FIRST
    [*] recv: {"ciphertext": "7341v2Ln7G/Lgpx34ZpzCQOAKI/T4B7iK44fmsoJBcgabqYEOOC/bOokofNBKtgwbLqFdvgH5+vxLtO3ZOg4YcyyIS/Np71v7SR1SZjhJaN9abVesj+bEhbD6MChs7Sf7jzOHYh0jsFAd5NmpcoCNOobNSdp5gkMv480vd0CDsMRRAGqAMGphAI59HJgKTNtmYBwEJFc6FES1HzYeHzhu9aaIqMTHYcdSxKWFoWagfs=", "iv": "gscGhye5j+M7UjKMhgXoSQ=="}
    [*] Plaintext: DATA:82024428564084747779838197048651633248611312289409527370705229681692303606145;39729181007633170694355209291478423286094320004491905477069339670330824477025
    [+] ECDSH key -> 72030276991425414947628627336807654469167727768166420584261307095702732572524
    '''
    global INIT_TIME_STAMP,clientSocket
    mykey = ECC.generate(curve=ECC_CURVE_TYPE)
    '''Object
    EccKey(curve='NIST P-256', 
    pointQ.x=18114350043767596730349465091312481083313243097682859381354351286602183506020, 
    pointQ.y=63110015274418413085315213523919658861446792810188426780956608784322546996660, d=6524771718440454949776512675598421268137783815297023420197407011486911596642)
    '''
    print(mykey)
    data = CIPHER_ID+str(mykey.pointQ.x)+";"+str(mykey.pointQ.y)
    key=str(int(INIT_TIME_STAMP)//100)
    key = f_sSHA256And32bytes(key+MASTER_PASS)
    info("AES key: "+key)
    
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    iv = b64e(iv).decode('utf-8')
    ct = b64e(ciphertext).decode('utf-8')

    result = json.dumps({'iv':iv, 'ciphertext':ct})

    result = f_sECBEncryptAndB64e(key,result)
    
    info("Ciphertext(send): "+ result)
    
    #下面是连锁协议，貌似没啥用。。。
    c1=b""
    c2=b""
    for i in range(len(result)):
        if (i%2==0):
            c1+=result[i]
        else:
            c2+=result[i]

    if FIRST:
        info("FIRST")
        time.sleep(0.5)
        clientSocket.sendall(c1)
        recMessage1 = clientSocket.recv(10240)
        time.sleep(0.5)
        clientSocket.sendall(c2)
        recMessage2 = clientSocket.recv(10240)
    else:
        info("LAST")
        recMessage1 = clientSocket.recv(10240)
        clientSocket.sendall(c1)
        recMessage2 = clientSocket.recv(10240)
        clientSocket.sendall(c2)
    recMessage = b""
    i=0
    j=0

    for cnt in range(len(recMessage1+recMessage2)):
        if (cnt%2==0):
            recMessage+=recMessage1[i]
            i+=1
        else:
            recMessage+=recMessage2[j]
            j+=1
    # 连锁结束

    recMessage = f_sECBDecryptAndB64d(key,recMessage)
    
    info("recv: "+ recMessage)
    b64 = json.loads(recMessage)
    iv = b64d(b64['iv'])
    ct = b64d(b64['ciphertext'])
    plain = AES.new(key, AES.MODE_CBC,iv)

    pt = unpad(plain.decrypt(ct), AES.block_size)
    info("Plaintext: "+str(pt))

    if (pt[0:len(CIPHER_ID)]!=CIPHER_ID):
        warn("You are under attack!")
        exit()
    
    x,y = pt[len(CIPHER_ID):].split(";")
    # 至此，公钥交换已经完成

    pFriendPublic = ECC.EccPoint(x,y,curve=ECC_CURVE_TYPE)
    keyP = mykey.d * pFriendPublic
    pFriendPublic = ECC.construct(curve=ECC_CURVE_TYPE,point_x = x,point_y = y)
    ECDH_Key = f_sSHA256And32bytes(str(keyP.x)+MASTER_PASS)
    success("ECDH key -> "+str(ECDH_Key))
    return ECDH_Key,mykey,pFriendPublic


def f_vCheckTime():
    '''
    time sychronizaion will be transmitted in an insecure channel
    '''
    global clientSocket,FIRST,INIT_TIME_STAMP
    fTimeNow = time.time()
    while (True):
        clientSocket.sendall(str(1))
        recMessage = clientSocket.recv(10240) 
        if (recMessage == '1'):
            clientSocket.sendall(str(1))
            break
    recMessage1 = clientSocket.recv(10240) 
    clientSocket.sendall(str(fTimeNow))
    recMessage = clientSocket.recv(10240) 
    clientSocket.sendall(str(fTimeNow))
    try:
        receive_message = recMessage[0:23].decode()
    except:
        warn("Check Time Failed")
        exit()
    fFriendTime = float(receive_message)
    info("Friend Timestamp: "+receive_message)
    if (abs(fFriendTime - fTimeNow) > TIME_SYNC_INTERREGNUM):
        warn("PLEASE SYNC TIME TO SERVER TIME or CHECK: " + time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(float(fFriendTime))))
        exit()
    success("P2P success")
    if fFriendTime<fTimeNow:
        FIRST = 1
        INIT_TIME_STAMP = fTimeNow
    
    if FIRST==0:
        recMessage = clientSocket.recv(10240)#接收上次的时间戳。。。
        INIT_TIME_STAMP = fFriendTime
    #清空垃圾消息
def f_bSendMsg(key,pubkey):
    global IS_EXIT
    cnt=1
    tmpkey = f_sSHA256And32bytes(key+MASTER_PASS)
    while not IS_EXIT:
        msg = raw_input("msg> ").decode(sys.stdin.encoding)
        
        data = MSG_ID + msg

        cipher = AES.new(key, AES.MODE_CBC)

        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))
        signer = DSS.new(pubkey, 'fips-186-3')
        hasher = SHA3_256.new(b64e(data.encode("utf-8"))) #Hash对象，对密文进行签名
        sign_obj = signer.sign(hasher)    #用私钥对消息签名

        iv = b64e(iv)
        ct = b64e(ciphertext)
        
        sg = b64e(sign_obj)
        cn = b64e(str(cnt))
        ts = b64e(str(time.time()))

        cnt += 1
        result = json.dumps({'iv':iv, 'sg':sg ,'ciphertext':ct, 'cn':cn, 'ts':ts})
        result = f_sECBEncryptAndB64e(tmpkey,result)
        clientSocket.sendall(result)
        
def f_vGetMsg(key,pubkey):
    global IS_EXIT
    cnt=0
    timest = 0
    tmpkey = f_sSHA256And32bytes(key+MASTER_PASS)
    while not IS_EXIT:
        recMessage = clientSocket.recv(10240)
        recMessage = f_sECBDecryptAndB64d(tmpkey, recMessage)
        msg = json.loads(recMessage)
        iv = b64d(msg['iv'])
        ct = b64d(msg['ciphertext'])
        sg = b64d(msg['sg'])
        cn = int(b64d(msg['cn']))
        ts = b64d(msg['ts'])
        if (cn - cnt < 0 or ts < timest):
            warn("Repeat Attack!")
            exit()

        plain = AES.new(key, AES.MODE_CBC,iv)
        pt = unpad(plain.decrypt(ct), AES.block_size)
        
        if (pt[0:len(MSG_ID)]!=MSG_ID):
            warn("MSG Decrypt Failed")
            exit()
        
        cnt=max(cnt,cn)
        timest=max(timest,ts)

        hasher = SHA3_256.new(b64e(pt)) # 对收到的消息文本提取摘要
        verifer = DSS.new(pubkey, 'fips-186-3') # 使用公钥创建校验对象

        try:
            verifer.verify(hasher, sg) # 校验摘要（本来的样子）和收到并解密的签名是否一致
            #print("The signature is valid.")
        except (ValueError, TypeError):
            warn("The signature is not valid, and you are under attack")
            exit()
        print("["+time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()))+"]: "+pt[len(MSG_ID):].decode('utf-8'))



if __name__ =="__main__":
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    clientSocket = socket(AF_INET, SOCK_STREAM)

    try:
        clientSocket.connect((SERVERIP, SERVERPORT))
    except:
        warn("Connect to server failed")
        exit()
    success("Connected to "+SERVERIP)
    f_vCheckTime()
    ECDH_Key,mykey,pFriendPublic = f_lKeyExchange()
    t = threading.Thread(target=f_vGetMsg,args=(ECDH_Key,pFriendPublic))
    t.setDaemon(True)
    t.start()
    f_bSendMsg(ECDH_Key,mykey)
