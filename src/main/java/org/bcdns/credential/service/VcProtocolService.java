package org.bcdns.credential.service;


import cn.ac.caict.bid.model.BIDDocumentOperation;
import cn.ac.caict.bid.model.BIDpublicKeyOperation;
import cn.bif.model.crypto.KeyPairEntity;
import cn.bif.module.encryption.key.PrivateKeyManager;
import cn.hutool.core.date.DateUtil;
import cn.hutool.crypto.digest.SM3;
import com.alipay.antchain.bridge.commons.bcdns.*;
import com.alipay.antchain.bridge.commons.core.base.BIDInfoObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.CrossChainDomain;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentityType;
import org.bcdns.credential.dao.domain.VcRecordDomain;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class VcProtocolService {

    @Value("${object-identity-type}")
    private Integer objectIdentityType;

    @Value("${credential.version}")
    private String version;

    @Value("${sign-type}")
    private String signAlg;

    public AbstractCrossChainCertificate buildPTCVc(String issuerPrivateKey, String issuerId,  String vcId, VcRecordDomain domain) {
        PTCContentEntity ptcContentEntity = PTCContentEntity.decode(domain.getContent());
        ObjectIdentity applicantObjectIdentity = ptcContentEntity.getApplicant();
        String context = "https://www.w3.org/2018/credentials/v1";
        //bid document info
        BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[2];
        biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
        biDpublicKeyOperation[0].setPublicKeyHex(ptcContentEntity.getPublicKey());
        BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
        bidDocumentOperation.setPublicKey(biDpublicKeyOperation);
        BIDInfoObjectIdentity bidInfoObjectIdentity = new BIDInfoObjectIdentity(bidDocumentOperation);

        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                context,
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new PTCCredentialSubject(
                        CrossChainCertificateV1.MY_VERSION,
                        "ptc_verifiable_credential",
                        ptcContentEntity.getType(),
                        applicantObjectIdentity,
                        bidInfoObjectIdentity.encode()
                )
        );

        PrivateKeyManager privateKeyManager = new PrivateKeyManager(issuerPrivateKey);
        byte[] msg = certificate.getEncodedToSign();
        byte[] sign = privateKeyManager.sign(msg);
        certificate.setProof(
                new AbstractCrossChainCertificate.IssueProof(
                        "SM3",
                        SM3.create().digest(certificate.getEncodedToSign()),
                        "SM2",
                        sign
                )
        );
        return certificate;
    }

    public AbstractCrossChainCertificate buildRelayVc(String issuerPrivateKey, String issuerId, String vcId, VcRecordDomain domain) {
        RelayContentEntity relayContentEntity = RelayContentEntity.decode(domain.getContent());
        ObjectIdentity applicantObjectIdentity = relayContentEntity.getApplicant();
        String context = "https://www.w3.org/2018/credentials/v1";
        //bid document info
        BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[2];
        biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
        biDpublicKeyOperation[0].setPublicKeyHex(relayContentEntity.getPublicKey());
        BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
        bidDocumentOperation.setPublicKey(biDpublicKeyOperation);
        BIDInfoObjectIdentity bidInfoObjectIdentity = new BIDInfoObjectIdentity(bidDocumentOperation);

        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                context,
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new RelayerCredentialSubject(
                        CrossChainCertificateV1.MY_VERSION,
                        "relay_verifiable_credential",
                        applicantObjectIdentity,
                        bidInfoObjectIdentity.encode()
                )
        );

        PrivateKeyManager privateKeyManager = new PrivateKeyManager(issuerPrivateKey);
        byte[] msg = certificate.getEncodedToSign();
        byte[] sign = privateKeyManager.sign(msg);
        certificate.setProof(
                new AbstractCrossChainCertificate.IssueProof(
                        "SM3",
                        SM3.create().digest(certificate.getEncodedToSign()),
                        "SM2",
                        sign
                )
        );
        return certificate;
    }

    public AbstractCrossChainCertificate buildDomainNameVc(String issuerPrivateKey, String issuerId,  String vcId, VcRecordDomain domain){
        DomainNameContentEntity domainNameContentEntity = DomainNameContentEntity.decode(domain.getContent());
        ObjectIdentity applicantObjectIdentity =  domainNameContentEntity.getApplicant();
        String context = "https://www.w3.org/2018/credentials/v1";
        //bid document info
        BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[2];
        biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
        biDpublicKeyOperation[0].setPublicKeyHex(domainNameContentEntity.getPublicKey());
        BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
        bidDocumentOperation.setPublicKey(biDpublicKeyOperation);
        BIDInfoObjectIdentity bidInfoObjectIdentity = new BIDInfoObjectIdentity(bidDocumentOperation);

        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                context,
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new DomainNameCredentialSubject(
                        CrossChainCertificateV1.MY_VERSION,
                        DomainNameTypeEnum.DOMAIN_NAME,
                        new CrossChainDomain("."),
                        domainNameContentEntity.getDomainName(),
                        applicantObjectIdentity,
                        bidInfoObjectIdentity.encode()
                )
        );

        PrivateKeyManager privateKeyManager = new PrivateKeyManager(issuerPrivateKey);
        byte[] msg = certificate.getEncodedToSign();
        byte[] sign = privateKeyManager.sign(msg);
        certificate.setProof(
                new AbstractCrossChainCertificate.IssueProof(
                        "SM3",
                        SM3.create().digest(certificate.getEncodedToSign()),
                        "SM2",
                        sign
                )
        );
        return certificate;
    }
}
