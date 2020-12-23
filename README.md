# Secure P2P Chat Python

@2020-12-24

keywords：ECDH，ECDSA，DSS， interlock protocol，AES，SHA3-256，Timestamp、Counter、MAC

关键技术：椭圆曲线DH密钥协商、椭圆曲线数字签名、连锁协议、AES、SHA3-256、时间戳、计数器、消息鉴别码

简介：期末复习摸鱼写的。

# REQUIREMENT

环境：python 2.7

你可以运行  `pip install -r this.txt`

```python
win_inet_pton
PyCryptodome
```

 if you run client in Windows: `win_inet_pton`

# 部署

安装好依赖之后，在

**服务器端**

```
nohup > /dev/null 2>&1 python server.py &
```

接下来在客户端配置好服务端的IP与端口就能运行了。

**客户端**

```
python client.py
```

# 实现逻辑

## 关键变量

`MASTER_PASS`，主密钥

``SERVERIP`` = "xx.xx.xx.xx"

`SERVERPORT `= 8888

`MASTER_PASS `= "dhwoahuhrwahdwdwadwadwadwad"

`TIME_SYNC_INTERREGNUM `= 10 # less than 99

`CIPHER_ID `= "DATA:" #密钥交换时的数据头部标识

`MSG_ID `= "CHATTING_MSG:" #信息传递时的数据头部标识

`ECC_CURVE_TYPE `= 'P-256'

`FIRST `= 0 #标记发送与接收的先后顺序

`INIT_TIME_STAMP `= 0

`IS_EXIT `= False #用来标记是否按下了`CTRL-C`



## 如何交换秘钥

明文传输：`f_vCheckTime`，两端互相交换时间戳，时间戳差必须小于`TIME_SYNC_INTERREGNUM`。这里还有个Bug就是两端必须几乎同时上限，。根据时间戳的大小给出之后发送数据的先后顺序（不知道还有没有更好的解决方法）

密文传输：`f_lKeyExchange`，两端进行ECDH密钥协商，椭圆曲线选用`P-256`，发送的公钥及其经过AES-CBC-256加密，而AES的口令来自对`MASTER_PASS`与`Timestamp`的SHA3-256（即，其是动态key）。

`f_lKeyExchange`效果：

```shell
	[+] Connected to 192.168.43.143
    [*] Friend Timestamp: 160xxxxxxx
    [+] P2P success
    [*] AES key: 07123f4xxxxxxxxxxxxxxxxxxx
    [*] Ciphertext(send): S7iUb3ANbK+COE85TnEp8PDeIdkUgayJ3Qhc8t5Pc30saMUosvntFESnPqPBuXYbETQ96rwlsWg6YUlMxwzYiex4HKrP9y3K5J1J8a8oSghJsCocjfu+KN1B7wJ1/6wWbbvi/N2yGaAMvhHIjSpONQDoTZDnUw3T8Rx+t5k4Ab154hOPPIetmSFdXdRrXOemuAQgxvXxkDhbrOPb1SQzV1+FmKdXKYQe2gRsPULvc14=
    [*] FIRST
    [*] recv: {"ciphertext": "7341v2Ln7G/Lgpx34ZpzCQOAKI/T4B7iK44fmsoJBcgabqYEOOC/bOokofNBKtgwbLqFdvgH5+vxLtO3ZOg4YcyyIS/Np71v7SR1SZjhJaN9abVesj+bEhbD6MChs7Sf7jzOHYh0jsFAd5NmpcoCNOobNSdp5gkMv480vd0CDsMRRAGqAMGphAI59HJgKTNtmYBwEJFc6FES1HzYeHzhu9aaIqMTHYcdSxKWFoWagfs=", "iv": "gscGhye5j+M7UjKMhgXoSQ=="}
    [*] Plaintext: DATA:82024428564084747779838197048651633248611312289409527370705229681692303606145;39729181007633170694355209291478423286094320004491905477069339670330824477025
    [+] ECDSH key -> b9dffa673314114e2104f59be28d47e1
```

还是在`f_lKeyExchange`里，有连锁协议（不知道能不能对MITM造成干扰...），最后的数据大概是先经过AES-CBC-256，然后诸如计数器、时间戳、数字签名、IV打包成json然后base64编码，接着再进行AES-ECB-256，最后再一次base64。

## 如何通讯

密钥交换完成后，如上所示有一个`[+] ECDSH key -> b9dffa673314114e2104f59be28d47e1`，这个密钥就是后面AES-CBC-256需要用的。

接下来自然就是发送信息与接收信息，我用了多线程实现。

密文传输：`f_bSendMsg`，这里还是和上面一样，发送的数据经过两次AES加密（ECB密钥与CBC密钥不同），数字签名是`fips-186-3`，使用时间戳与计数器抵抗重放。 

# 致谢

Server代码修改自<https://github.com/artificial-retarded/chatting>