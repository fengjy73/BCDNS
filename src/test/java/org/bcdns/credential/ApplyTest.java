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
        PrivateKeyManager privateKeyManager = new PrivateKeyManager("priSPKeThUrwmBvigbe153GWQXRDuMUWwpM8fRBs4eQ82sQSgQ");
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
                        PTCTypeEnum.BLOCKCHAIN,
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
        PrivateKeyManager privateKeyManager = new PrivateKeyManager("priSPKeThUrwmBvigbe153GWQXRDuMUWwpM8fRBs4eQ82sQSgQ");
        BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[1];
        biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
        biDpublicKeyOperation[0].setType(KeyType.ED25519);
        biDpublicKeyOperation[0].setPublicKeyHex("b06566d3ba095bb576e8d75b9e39a3d06cdf6deb25f93d526f13040c5df9cd6c27be8e");
        BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
        bidDocumentOperation.setPublicKey(biDpublicKeyOperation);

        PublicKeyManager publicKeyManager = new PublicKeyManager("b06566d3ba095bb576e8d75b9e39a3d06cdf6deb25f93d526f13040c5df9cd6c27be8e");

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
