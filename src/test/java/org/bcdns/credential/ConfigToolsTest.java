package org.bcdns.credential;

import cn.bif.module.encryption.key.PrivateKeyManager;
import cn.bif.module.encryption.key.PublicKeyManager;
import cn.bif.module.encryption.model.KeyMember;
import cn.bif.module.encryption.model.KeyType;
import cn.bif.utils.base.Base58;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.BCUtil;
import cn.hutool.crypto.PemUtil;
import com.alibaba.druid.filter.config.ConfigTools;
import com.alipay.antchain.bridge.commons.bcdns.AbstractCrossChainCertificate;
import com.alipay.antchain.bridge.commons.bcdns.CrossChainCertificateFactory;
import com.alipay.antchain.bridge.commons.bcdns.RelayerCredentialSubject;
import com.alipay.antchain.bridge.commons.bcdns.utils.CrossChainCertificateUtil;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentityType;
import com.alipay.antchain.bridge.commons.core.base.X509PubkeyInfoObjectIdentity;
import com.alipay.antchain.bridge.commons.utils.crypto.SignAlgoEnum;
import com.google.gson.JsonObject;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static com.alibaba.druid.filter.config.ConfigTools.*;

public class ConfigToolsTest {
    @Test
    public void testCreateKeyPair() throws Exception {
        String[] arr = genKeyPair(512);
        System.out.println("privateKey:" + arr[0]);
        System.out.println("publicKey:" + arr[1]);
    }

    @Test
    public void testEncrypt() throws Exception {
        String password = "123456";
        String privateKey = "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAunLtL3wVMCmLCj9TrMEkAYLIYu26pk2FGYkKg1wKnufxeToMOGgFa3B44b2/uE+ojlg3/q07maQW36cPEf6SRwIDAQABAkBoBb63A29+026zZOl2NLu17BWIvEGqjw13VbH739o9FQ5R20jI10Ypq83Gsg7eLkTXTlkSQ4W1UNJZCM9//xQBAiEA7VKb/g6wve1WYeDbsWcCHbFV06mBtvwCHqNWzQyDvYECIQDJH1pKg6t3xIzqw9TwNbWXJZPoJrRTdbwhHGSWFr3DxwIhAILYSgMvzEha44aBd/7+YQ9H558UVN0zYmPMAJ566OOBAiBFR26Dwm1bOTJNYB3GjMm7ge88BbESGrkuMqiXZsgBWwIhALYOVdvMW+BWLC+9WMwz4TwnpmJcxSAIPGP3ijX2Et9e";
        System.out.println("password:" + encrypt(privateKey, password));
    }

    @Test
    public void testSM2Sign() throws Exception {
        String msgToSign = "test";
        PrivateKeyManager privateKeyManager = new PrivateKeyManager ("priSrrUQpUphw5Prri5qmaPfc5TjuUuK4L11rKqE7LUXEmds12");
        byte[] sig = privateKeyManager.sign(msgToSign.getBytes());

        BigInteger n = new BigInteger("115792089210356248756420345214020892766061623724957744567843809356293439045923");

        sig = StandardDSAEncoding.INSTANCE.encode(n, new BigInteger(1, ArrayUtil.sub(sig, 0, 32)), new BigInteger(1, ArrayUtil.sub(sig, 32, 64)));

        PublicKey publicKey1 = BCUtil.decodeECPoint(privateKeyManager.getRawPublicKey(), "sm2p256v1");
        System.out.println(HexUtil.encodeHex(sig));
        Assert.assertTrue(SignAlgoEnum.SM3_WITH_SM2.getSigner().verify(publicKey1, msgToSign.getBytes(), sig));
    }

    @Test
    public void getPrivateKeyFromPem() throws Exception {
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                "MFECAQEwBQYDK2VwBCIEIMpri3D+Tj7nzsIX+3LZYDOmX/l4Nkh/b9QMy3l8C7Vd\n" +
                "gSEAc3MsC0L0rwJipeino+phnkBwMhJ4InocBQmqDtmbh1s=\n" +
                "-----END PRIVATE KEY-----";
        byte[] rawOctetStr = PrivateKeyInfo.getInstance(
                PemUtil.readPem(new ByteArrayInputStream(privateKeyPem.getBytes()))
        ).getPrivateKey().getOctets();
        KeyMember keyMember = new KeyMember();
        keyMember.setRawSKey(ArrayUtil.sub(rawOctetStr, 2, rawOctetStr.length));
        keyMember.setKeyType(KeyType.ED25519);
        System.out.println(PrivateKeyManager.getEncPrivateKey(keyMember.getRawSKey(), keyMember.getKeyType()));
        PrivateKeyManager privateKeyManager = new PrivateKeyManager(PrivateKeyManager.getEncPrivateKey(keyMember.getRawSKey(), keyMember.getKeyType()));
        System.out.println(privateKeyManager.getEncPrivateKey());
        System.out.println(privateKeyManager.getEncPublicKey());
        System.out.println(privateKeyManager.getEncAddress());
    }

    @Test
    public void getPublicKeyFromBase64() throws Exception {
        String rawBase64 = "MCowBQYDK2VwAyEAc3MsC0L0rwJipeino+phnkBwMhJ4InocBQmqDtmbh1s=";
        ObjectIdentity objectIdentity = new X509PubkeyInfoObjectIdentity(Base64.decode(rawBase64));
        System.out.println(objectIdentity.getType());
        System.out.println(objectIdentity.toHex());

        System.out.println(HexUtil.encodeHexStr(objectIdentity.getRawId()));
    }

    @Test
    public void getAddressFromBase64() throws Exception {
        String rawBase64 = "MCowBQYDK2VwAyEAc3MsC0L0rwJipeino+phnkBwMhJ4InocBQmqDtmbh1s=";
        ObjectIdentity objectIdentity = ObjectIdentity.decode(Base64.decode(rawBase64));
        //ObjectIdentity objectIdentity = new ObjectIdentity(ObjectIdentityType.BID, Base64.decode(rawBase64));
        //PrivateKeyManager privateKeyManager = new PrivateKeyManager(Base64.encode(privateKeyBase64));
//        System.out.println(privateKeyManager.getEncPrivateKey());
//        System.out.println(privateKeyManager.getEncPublicKey());
        System.out.println(objectIdentity.getType());
        System.out.println(new String(objectIdentity.getRawId()));
    }

    @Test
    public void getCertInfoBase64() throws Exception {
        String cert = "-----BEGIN RELAYER CERTIFICATE-----\n" +
                "AACUAQAAAAABAAAAMQEAKAAAAGRpZDpiaWQ6ZWZEYm45QXRDaGlxdlAydFU0ZlJo\n" +
                "VThTQ0I1WnI0eFcCAAEAAAADAwA7AAAAAAA1AAAAAAABAAAAAQEAKAAAAGRpZDpi\n" +
                "aWQ6ZWZrZFlIemNnTGlISENxMVNLYXlNdHFWSHB4dmVTREQEAAgAAACc5jFnAAAA\n" +
                "AAUACAAAABwaE2kAAAAABgBnAAAAAABhAAAAAAABAAAAMQEACQAAAG15cmVsYXll\n" +
                "cgMAPwAAAAAAOQAAAAAAAQAAAAABACwAAAAwKjAFBgMrZXADIQBzcywLQvSvAmKl\n" +
                "6Kej6mGeQHAyEngiehwFCaoO2ZuHWwQAAAAAAAcAiAAAAAAAggAAAAAAAwAAAFNN\n" +
                "MwEAIAAAAPJkoa+TkO/KOOmSzpuROLtiG0NMpffjFZYu8fC/OKm0AgAHAAAARWQy\n" +
                "NTUxOQMAQAAAALUNVVHfCpMyTsj+6sR9Wn79O+tbUMxrWTbyIbpsiyWX088SfZ9F\n" +
                "s0nA0ojOetel+E+dnHynHraXDql1VPVwago=\n" +
                "-----END RELAYER CERTIFICATE-----";
        AbstractCrossChainCertificate certificate = CrossChainCertificateUtil.readCrossChainCertificateFromPem(cert.getBytes());
        System.out.println(certificate.getType());
        System.out.println(certificate.getId());
        System.out.println(certificate.getIssuer().getType());
        System.out.println(new String(certificate.getIssuer().getRawId()));
        RelayerCredentialSubject relayerCredentialSubject = RelayerCredentialSubject.decode(certificate.getCredentialSubject());

        ObjectIdentity objectIdentity = new X509PubkeyInfoObjectIdentity(relayerCredentialSubject.getApplicant());

        System.out.println(new X509PubkeyInfoObjectIdentity(relayerCredentialSubject.getApplicant()).getType());
        //System.out.println(relayerCredentialSubject.getApplicant().getType());
        System.out.println(new X509PubkeyInfoObjectIdentity(relayerCredentialSubject.getApplicant()).getPublicKey().getAlgorithm());
        System.out.println(new X509PubkeyInfoObjectIdentity(relayerCredentialSubject.getApplicant()).getPublicKey().getFormat());
        System.out.println(HexUtil.encodeHexStr(new X509PubkeyInfoObjectIdentity(relayerCredentialSubject.getApplicant()).getRawId()));
    }

    @Test
    public void getBcdnsCertHerStr() throws Exception {
        System.out.println(
                HexUtil.encodeHexStr(
                        CrossChainCertificateUtil.readCrossChainCertificateFromPem(("-----BEGIN BCDNS TRUST ROOT CERTIFICATE-----\n" +
                                "AAAUAgAAAAABAAAAMQEAKAAAAGRpZDpiaWQ6ZWZDNVF2b1I5VXd2WG91c0pCMk1v\n" +
                                "cjFyM2pXRGZTQUMCAAEAAAAAAwA7AAAAAAA1AAAAAAABAAAAAQEAKAAAAGRpZDpi\n" +
                                "aWQ6ZWYxNm1hdVc5dWtCYkxxWXBiWjhiN2JhdlhUUGVHTUMEAAgAAAC2oSRnAAAA\n" +
                                "AAUACAAAADbVBWkAAAAABgDnAAAAAADhAAAAAAAaAAAAcm9vdF92ZXJpZmlhYmxl\n" +
                                "X2NyZWRlbnRpYWwBADsAAAAAADUAAAAAAAEAAAABAQAoAAAAZGlkOmJpZDplZmtk\n" +
                                "WUh6Y2dMaUhIQ3ExU0theU10cVZIcHh2ZVNERAIAegAAAHsicHVibGljS2V5Ijpb\n" +
                                "eyJ0eXBlIjoiRUQyNTUxOSIsInB1YmxpY0tleUhleCI6ImIwNjU2NmI4NzU1NGNl\n" +
                                "MTg4MDRhMTMxNTdmMDAyN2Q5MzZjNjM3N2JmYmNiZjI0NDU3OGU5M2Q3NjFkYTU1\n" +
                                "YjQ1OTFjMjkifV19BwCIAAAAAACCAAAAAAADAAAAU00zAQAgAAAAkopJIjppgy5h\n" +
                                "LzMI97hWL7BwFZAkpG0i1gj9MWZcniICAAcAAABFZDI1NTE5AwBAAAAA/8FDdtsU\n" +
                                "hJ5LEyMqFKYnm6Klzo0UPIlxuBZcusmIkZPBjm4XtmvvI2b5WbhYsMzt7feXz16H\n" +
                                "BoMJ+kdmMiH4Dw==\n" +
                                "-----END BCDNS TRUST ROOT CERTIFICATE-----").getBytes()).encode()
                )
        );
    }

    @Test
    public void getSDP() throws Exception {
        String address = "SDP_EVM_CONTRACT_cebb48d0-359b-4068-97ad-654b8b443c01";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(address.getBytes(StandardCharsets.UTF_8));
        System.out.println(HexUtil.encodeHexStr(hash));
    }

}
