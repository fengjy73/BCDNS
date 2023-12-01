package org.bcdns.credential.service;


import cn.bif.model.crypto.KeyPairEntity;
import cn.bif.module.encryption.key.PrivateKeyManager;
import cn.bif.module.encryption.model.KeyType;
import cn.hutool.core.date.DateUtil;
import cn.hutool.crypto.digest.SM3;
import com.alipay.antchain.bridge.commons.bcdns.*;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentityType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.bcdns.credential.model.VcRecordDomain;

import java.util.Date;

@Service
public class VcProtocolService {

    public AbstractCrossChainCertificate buildPTCVc(String issuerPrivateKey, String issuerId,  String vcId, VcRecordDomain domain) {
        AbstractCrossChainCertificate cert = CrossChainCertificateFactory.createCrossChainCertificate(domain.getContent());
        PTCCredentialSubject ptcCredentialSubject = PTCCredentialSubject.decode(cert.getCredentialSubject());
        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new PTCCredentialSubject(
                        ptcCredentialSubject.getVersion(),
                        ptcCredentialSubject.getName(),
                        ptcCredentialSubject.getType(),
                        ptcCredentialSubject.getApplicant(),
                        ptcCredentialSubject.getSubjectInfo()
                )
        );

        PrivateKeyManager privateKeyManager = new PrivateKeyManager(issuerPrivateKey);
        byte[] msg = certificate.getEncodedToSign();
        byte[] sign = privateKeyManager.sign(msg);
        String signAlg = "";
        KeyType keyType = privateKeyManager.getKeyType();
        if (keyType.equals(KeyType.SM2)) {
            signAlg = "SM2";
        } else if (keyType.equals(KeyType.ED25519)){
            signAlg = "Ed25519";
        }
        certificate.setProof(
                new AbstractCrossChainCertificate.IssueProof(
                        "SM3",
                        SM3.create().digest(certificate.getEncodedToSign()),
                        signAlg,
                        sign
                )
        );
        return certificate;
    }

    public AbstractCrossChainCertificate buildRelayVc(String issuerPrivateKey, String issuerId, String vcId, VcRecordDomain domain) {
        AbstractCrossChainCertificate cert = CrossChainCertificateFactory.createCrossChainCertificate(domain.getContent());
        RelayerCredentialSubject relayerCredentialSubject = RelayerCredentialSubject.decode(cert.getCredentialSubject());
        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new RelayerCredentialSubject(
                        relayerCredentialSubject.getVersion(),
                        relayerCredentialSubject.getName(),
                        relayerCredentialSubject.getApplicant(),
                        relayerCredentialSubject.getSubjectInfo()
                )
        );

        PrivateKeyManager privateKeyManager = new PrivateKeyManager(issuerPrivateKey);
        byte[] msg = certificate.getEncodedToSign();
        byte[] sign = privateKeyManager.sign(msg);
        String signAlg = "";
        KeyType keyType = privateKeyManager.getKeyType();
        if (keyType.equals(KeyType.SM2)) {
            signAlg = "SM2";
        } else if (keyType.equals(KeyType.ED25519)){
            signAlg = "Ed25519";
        }
        certificate.setProof(
                new AbstractCrossChainCertificate.IssueProof(
                        "SM3",
                        SM3.create().digest(certificate.getEncodedToSign()),
                        signAlg,
                        sign
                )
        );
        return certificate;
    }

    public AbstractCrossChainCertificate buildDomainNameVc(String issuerPrivateKey, String issuerId,  String vcId, VcRecordDomain domain){
        AbstractCrossChainCertificate cert = CrossChainCertificateFactory.createCrossChainCertificate(domain.getContent());
        DomainNameCredentialSubject domainNameCredentialSubject = DomainNameCredentialSubject.decode(cert.getCredentialSubject());
        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new DomainNameCredentialSubject(
                        domainNameCredentialSubject.getVersion(),
                        domainNameCredentialSubject.getDomainNameType(),
                        domainNameCredentialSubject.getParentDomainSpace(),
                        domainNameCredentialSubject.getDomainName(),
                        domainNameCredentialSubject.getApplicant(),
                        domainNameCredentialSubject.getSubject()
                )
        );

        PrivateKeyManager privateKeyManager = new PrivateKeyManager(issuerPrivateKey);
        byte[] msg = certificate.getEncodedToSign();
        byte[] sign = privateKeyManager.sign(msg);
        String signAlg = "";
        KeyType keyType = privateKeyManager.getKeyType();
        if (keyType.equals(KeyType.SM2)) {
            signAlg = "SM2";
        } else if (keyType.equals(KeyType.ED25519)){
            signAlg = "Ed25519";
        }
        certificate.setProof(
                new AbstractCrossChainCertificate.IssueProof(
                        "SM3",
                        SM3.create().digest(certificate.getEncodedToSign()),
                        signAlg,
                        sign
                )
        );
        return certificate;
    }
}
