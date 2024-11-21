# 申请参数工具类

1、工具类jar包（BCDNS-tool-1.0-SNAPSHOT-jar-with-dependencies.jar）

2、在jar包目录下用命令行执行 

### **申请PTC参数：**

| 参数号 | 说明                                                         |
| ------ | ------------------------------------------------------------ |
| 0      | 值为ptc，指定为申请ptc证书                                   |
| 1      | 申请人私钥，ptc只能由超级节点申请                            |
| 2      | ptc的公钥                                                    |
| 3      | ptc的类型，0为外部验证者模式、1为委员会验证模式、2为中继验证模式 |
| 4      | 签名算法ed25519、sm2，需要和ptc的公钥相匹配                  |

```
java -cp BCDNS-tool-1.0-SNAPSHOT-jar-with-dependencies.jar org.example.ApplyTool ptc 申请人的私钥 ptc的公钥 ptc的type 签名算法
```
### **申请relay（中继）参数：**

| 参数号 | 说明                                        |
| ------ | ------------------------------------------- |
| 0      | 值为relay，指定为申请relay证书              |
| 1      | 申请人私钥，中继只能由超级节点申请          |
| 2      | relay的公钥                                 |
| 3      | 签名算法ed25519、sm2，需要和ptc的公钥相匹配 |

```
java -cp BCDNS-tool-1.0-SNAPSHOT-jar-with-dependencies.jar org.example.ApplyTool relay 申请人的私钥 relay的公钥 签名算法
```

### **申请域名参数：**

| 参数号 | 说明                                        |
| ------ | ------------------------------------------- |
| 0      | 值为domainName，指定为申请区块链域名证书    |
| 1      | 申请人私钥，区块链域名只能由中继代为申请    |
| 2      | 区块链的公钥                                |
| 3      | 区块链域名                                  |
| 4      | 签名算法ed25519、sm2，需要和ptc的公钥相匹配 |

```
java -cp BCDNS-tool-1.0-SNAPSHOT-jar-with-dependencies.jar org.example.ApplyTool domainName 申请人的私钥 区块链的公钥 申请的区块链域名 签名算法
```

### **注册PTCTrustRoot参数：**

| 参数号 | 说明                                      |
| ------ | ----------------------------------------- |
| 0      | 值为newPtcTrustRoot，指定注册PTCTrustRoot |
| 1      | ptc的证书，为Base64编码格式               |
| 2      | ptc的私钥，用于对TructRoot签名            |

```
java -cp BCDNS-tool-1.0-SNAPSHOT-jar-with-dependencies.jar org.example.ApplyTool newPtcTrustRoot ptc的证书 ptc的私钥
```

### **解析CRS（Certificate Signing Request）即证书签名请求文件**

CRS由relay和ptc的CLI命令生成

| 参数号 | 说明              |
| ------ |-----------------|
| 0      | 值为CSR，指定解析CRS文件 |
| 1      | 中继或者ptc的私钥，用于签名 |
| 2      | CSR文件内容         |

```
java -cp BCDNS-tool-1.0-SNAPSHOT-jar-with-dependencies.jar org.example.ApplyTool CSR 私钥 CSR文件
```

### **BIF地址转化为bytes32类型**

| 参数号 | 说明                 |
| ------ | -------------------- |
| 0      | getBifAddressBytes32 |
| 1      | 地址                 |

```
java -cp BCDNS-tool-1.0-SNAPSHOT-jar-with-dependencies.jar org.example.ApplyTool getBifAddressBytes32 地址
```

### **Mychain的SDP合约转化为bytes32**

| 参数号 | 说明                                                         |
| ------ | ------------------------------------------------------------ |
| 0      | getMyChainSDPBytes32                                         |
| 1      | MyChain的SDP系统合约的地址，在r-cli终端通过get-blockchain-contracts命令查询，例如SDP_EVM_CONTRACT_cebb48d0-359b-4068-97ad-654b8b443c01 |

```
java -cp BCDNS-tool-1.0-SNAPSHOT-jar-with-dependencies.jar org.example.ApplyTool getBifAddressBytes32 SDP合约地址
```

