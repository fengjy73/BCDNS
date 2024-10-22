package org.bcdns.credential;

import cn.ac.caict.bid.model.BIDDocumentOperation;
import cn.ac.caict.bid.model.BIDpublicKeyOperation;
import cn.bif.common.JsonUtils;
import cn.bif.model.crypto.KeyPairEntity;
import cn.bif.module.encryption.key.PrivateKeyManager;
import cn.bif.module.encryption.key.PublicKeyManager;
import cn.bif.module.encryption.model.KeyType;
import cn.hutool.core.date.DateUtil;
import com.alipay.antchain.bridge.commons.bcdns.*;
import com.alipay.antchain.bridge.commons.core.base.CrossChainDomain;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentityType;
import com.alipay.antchain.bridge.commons.core.ptc.PTCTypeEnum;
import org.junit.Test;

import java.util.Arrays;
import java.util.Date;

public class ApplyTest {
    @Test
    public void testPTCApply() throws Exception {
        PrivateKeyManager privateKeyManager = new PrivateKeyManager("priSPKncqxV7SR5bJgTWxBpLDAotDbBsrGNAVky34VKzLXHppi");
        KeyPairEntity keyPair = KeyPairEntity.getBidAndKeyPair();
        BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[1];
        biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
        PrivateKeyManager privateKeyManager1 = new PrivateKeyManager(keyPair.getEncPrivateKey());
        biDpublicKeyOperation[0].setType(privateKeyManager1.getKeyType());
        biDpublicKeyOperation[0].setPublicKeyHex(keyPair.getEncPublicKey());
        BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
        bidDocumentOperation.setPublicKey(biDpublicKeyOperation);

        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, privateKeyManager.getEncAddress().getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new PTCCredentialSubject(
                        "1.0",
                        "test",
                        PTCTypeEnum.COMMITTEE,
                        new ObjectIdentity(ObjectIdentityType.BID, keyPair.getEncAddress().getBytes()),
                        JsonUtils.toJSONString(bidDocumentOperation).getBytes()
                )
        );

        byte[] msg = certificate.getEncodedToSign();
        System.out.println("content:" + Arrays.toString(msg));
        System.out.println("credentialType:" + 2);
        String publicKey = privateKeyManager.getEncPublicKey();
        System.out.println("publicKey:" + publicKey);
        byte[] sign = privateKeyManager.sign(msg);
        System.out.println("sign:" + Arrays.toString(sign));
    }

    @Test
    public void testRelayApply() throws Exception {
        PrivateKeyManager privateKeyManager = new PrivateKeyManager("priSPKeThUrwmBvigbe153GWQXRDuMUWwpM8fRBs4eQ82sQSgQ");
        KeyPairEntity keyPair = KeyPairEntity.getBidAndKeyPair();
        BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[1];
        biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
        PrivateKeyManager privateKeyManager1 = new PrivateKeyManager(keyPair.getEncPrivateKey());
        biDpublicKeyOperation[0].setType(privateKeyManager1.getKeyType());
        biDpublicKeyOperation[0].setPublicKeyHex(keyPair.getEncPublicKey());
        BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
        bidDocumentOperation.setPublicKey(biDpublicKeyOperation);

        System.out.println("Relay privateKey:" + keyPair.getEncPrivateKey());
        System.out.println("Relay publicKey:" + keyPair.getEncPublicKey());
        System.out.println("Relay address:" + keyPair.getEncAddress());

        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, privateKeyManager.getEncAddress().getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new RelayerCredentialSubject(
                        RelayerCredentialSubject.CURRENT_VERSION,
                        "relay",
                        new ObjectIdentity(ObjectIdentityType.BID, keyPair.getEncAddress().getBytes()),
                        JsonUtils.toJSONString(bidDocumentOperation).getBytes()
                )
        );

        byte[] msg = certificate.getEncodedToSign();
        System.out.println("content:" + Arrays.toString(msg));
        System.out.println("credentialType:" + 3);
        String publicKey = privateKeyManager.getEncPublicKey();
        System.out.println("publicKey:" + publicKey);
        byte[] sign = privateKeyManager.sign(msg);
        System.out.println("sign:" + Arrays.toString(sign));
    }

    @Test
    public void testRelayApply01() throws Exception {
//        "address": "did:bid:efNurcfDs2XFV75jUFvi3MqYJuyphxjk",
//        "address_raw": "4f2497ec8d46137410df0436115ef2385ec22ac17ddb",
//        "private_key": "priSPKncqxV7SR5bJgTWxBpLDAotDbBsrGNAVky34VKzLXHppi",
//        "private_key_aes": "b6be1758109f9b3f51553cfe1322d84b8eb80e46e88948bfd8624f0d53315a0f75ecbde55b4ab24deda45093566436b26b44fdc4a513e4a29742335f7fac74b9",
//        "public_key": "b065662fdd2fb283d72aa829e7694e0675c0b8ded947dfa64b0b4768ccea8b30f06801",
//        "public_key_raw": "2fdd2fb283d72aa829e7694e0675c0b8ded947dfa64b0b4768ccea8b30f06801",
//        "sign_type": "ed25519"
        PrivateKeyManager privateKeyManager = new PrivateKeyManager("priSPKo5zX8nHexxod3YNyuUzo5DeHyZXFHdizh5LYLUN3ZTSX");
        BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[1];
        biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
        biDpublicKeyOperation[0].setType(KeyType.ED25519);
        biDpublicKeyOperation[0].setPublicKeyHex("b0656687609e5254aaf4617b0f27904a477490b1952ec07eeac4dc7a00f90614e15adb");
        BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
        bidDocumentOperation.setPublicKey(biDpublicKeyOperation);

        PublicKeyManager publicKeyManager = new PublicKeyManager("b0656687609e5254aaf4617b0f27904a477490b1952ec07eeac4dc7a00f90614e15adb");

        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, privateKeyManager.getEncAddress().getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new RelayerCredentialSubject(
                        RelayerCredentialSubject.CURRENT_VERSION,
                        "relay",
                        new ObjectIdentity(ObjectIdentityType.BID, publicKeyManager.getEncAddress().getBytes()),
                        JsonUtils.toJSONString(bidDocumentOperation).getBytes()
                )
        );

        byte[] msg = certificate.getEncodedToSign();
        System.out.println("content:" + Arrays.toString(msg));
        System.out.println("credentialType:" + 3);
        String publicKey = privateKeyManager.getEncPublicKey();
        System.out.println("publicKey:" + publicKey);
        byte[] sign = privateKeyManager.sign(msg);
        System.out.println("sign:" + Arrays.toString(sign));
    }

    @Test
    public void testDomainNameApply() throws Exception {
        PrivateKeyManager privateKeyManager = new PrivateKeyManager("priSPKeThUrwmBvigbe153GWQXRDuMUWwpM8fRBs4eQ82sQSgQ");
        KeyPairEntity keyPair = KeyPairEntity.getBidAndKeyPair();
        BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[1];
        biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
        PrivateKeyManager privateKeyManager1 = new PrivateKeyManager(keyPair.getEncPrivateKey());
        biDpublicKeyOperation[0].setType(privateKeyManager1.getKeyType());
        biDpublicKeyOperation[0].setPublicKeyHex(keyPair.getEncPublicKey());
        BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
        bidDocumentOperation.setPublicKey(biDpublicKeyOperation);

        System.out.println("Domain name privateKey:" + keyPair.getEncPrivateKey());
        System.out.println("Domain name publicKey:" + keyPair.getEncPublicKey());
        System.out.println("Domain name address:" + keyPair.getEncAddress());

        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, privateKeyManager.getEncAddress().getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new DomainNameCredentialSubject(
                        DomainNameCredentialSubject.CURRENT_VERSION,
                        DomainNameTypeEnum.DOMAIN_NAME,
                        new CrossChainDomain(".com"),
                        new CrossChainDomain("bif.100"),
                        new ObjectIdentity(ObjectIdentityType.BID, keyPair.getEncAddress().getBytes()),
                        JsonUtils.toJSONString(bidDocumentOperation).getBytes()
                )
        );

        byte[] msg = certificate.getEncodedToSign();
        System.out.println("content:" + Arrays.toString(msg));
        System.out.println("credentialType:" + 1);
        String publicKey = privateKeyManager.getEncPublicKey();
        System.out.println("publicKey:" + publicKey);
        byte[] sign = privateKeyManager.sign(msg);
        System.out.println("sign:" + Arrays.toString(sign));
    }
}
