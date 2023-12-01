package org.bcdns.credential.biz;


import cn.ac.caict.bid.model.BIDDocumentOperation;
import cn.ac.caict.bid.model.BIDpublicKeyOperation;
import cn.bif.api.BIFSDK;
import com.alipay.antchain.bridge.commons.bcdns.utils.BIDHelper;
import com.alipay.antchain.bridge.commons.bcdns.utils.CrossChainCertificateUtil;
import com.alipay.antchain.bridge.commons.core.base.CrossChainDomain;
import cn.bif.model.crypto.KeyPairEntity;
import cn.bif.model.request.BIFContractInvokeRequest;
import cn.bif.model.response.BIFContractInvokeResponse;
import cn.bif.module.encryption.key.PrivateKeyManager;
import cn.bif.module.encryption.model.KeyType;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateUtil;
import cn.hutool.crypto.digest.SM3;
import com.alipay.antchain.bridge.commons.bcdns.*;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentityType;
import org.bcdns.credential.common.constant.Constants;
import org.bcdns.credential.common.utils.AppUtils;
import org.bcdns.credential.common.utils.JwtUtil;
import org.bcdns.credential.common.utils.RedisUtil;
import org.bcdns.credential.common.utils.Tools;
import org.bcdns.credential.model.*;
import org.bcdns.credential.dto.req.*;
import org.bcdns.credential.dto.resp.*;
import org.bcdns.credential.enums.CredentialApplyStatusEnum;
import org.bcdns.credential.enums.ExceptionEnum;
import org.bcdns.credential.enums.StatusEnum;
import org.bcdns.credential.exception.APIException;
import org.bcdns.credential.service.*;
import org.bcdns.credential.utils.DistributedLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.*;


@Component
public class VcInternalBiz {

    @Value("${object-identity.supernode.bid-private-key}")
    private String superNodeBidPrivateKey;

    @Value("${object-identity.issuer.bid-private-key}")
    private String issuerBidPrivateKey;

    @Value("${ptc.contract.address}")
    private String ptcContractAddress;

    @Value("${relay.contract.address}")
    private String relayContractAddress;

    @Value("${domain-name.contract.address}")
    private String domainNameContractAddress;

    @Value("${sdk.url}")
    private String sdkUrl;

    private static final Logger logger = LoggerFactory.getLogger(VcInternalBiz.class);

    @Autowired
    private ApiKeyService apiKeyService;
    @Autowired
    private VcRecordService vcRecordService;
    @Autowired
    private VcAuditService vcAuditService;
    @Autowired
    private VcProtocolService vcProtocolService;
    @Autowired
    private RedisUtil redisUtil;
    @Autowired
    private VcRootService vcRootService;

    @Autowired
    private DistributedLock distributedLock;

    public DataResp<ApiKeyRespDto> init() {
        DataResp<ApiKeyRespDto> dataResp = new DataResp<ApiKeyRespDto>();
        PrivateKeyManager superNodePrivateKeyManager = new PrivateKeyManager(superNodeBidPrivateKey);
        PrivateKeyManager issuerPrivateKeyManager = new PrivateKeyManager(issuerBidPrivateKey);
        try {
            ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyDomain(1);
            if (!Tools.isNull(apiKeyDomain) && apiKeyDomain.getInitTag().equals(1)) {
                throw new APIException(ExceptionEnum.PLATFORM_REPEAT_INIT);
            }

            //create root vc
            BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[1];
            biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
            biDpublicKeyOperation[0].setType(issuerPrivateKeyManager.getKeyType());
            biDpublicKeyOperation[0].setPublicKeyHex(issuerPrivateKeyManager.getEncPublicKey());
            BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
            bidDocumentOperation.setPublicKey(biDpublicKeyOperation);

            AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                    CrossChainCertificateV1.MY_VERSION,
                    KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                    new ObjectIdentity(ObjectIdentityType.BID, superNodePrivateKeyManager.getEncAddress().getBytes()),
                    DateUtil.currentSeconds(),
                    DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                    new BCDNSTrustRootCredentialSubject(
                            "root_verifiable_credential",
                            new ObjectIdentity(ObjectIdentityType.BID, issuerPrivateKeyManager.getEncAddress().getBytes()),
                            JsonUtils.toJSONString(bidDocumentOperation).getBytes()
                    )
            );

            byte[] msg = certificate.getEncodedToSign();
            byte[] sign = superNodePrivateKeyManager.sign(msg);
            String signAlg = "";
            KeyType keyType = superNodePrivateKeyManager.getKeyType();
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

            byte[] cert = certificate.encode();
            VcRootDomain vcRootDomain = new VcRootDomain();
            vcRootDomain.setVcRoot(cert);
            vcRootService.insert(vcRootDomain);

            //create api key
            String apiKey = AppUtils.getAppId();
            String secret = AppUtils.getAppSecret(apiKey);
            ApiKeyDomain apiKeyDomain1 = new ApiKeyDomain();
            apiKeyDomain1.setApiKey(apiKey);
            apiKeyDomain1.setApiSecret(secret);
            apiKeyDomain1.setIssuerPrivateKey(issuerPrivateKeyManager.getEncPrivateKey());
            apiKeyDomain1.setIssuerId(issuerPrivateKeyManager.getEncAddress());
            apiKeyDomain1.setInitTag(1);
            apiKeyService.insert(apiKeyDomain1);

            ApiKeyRespDto apiKeyRespDto = new ApiKeyRespDto();
            apiKeyRespDto.setApiKey(apiKey);
            apiKeyRespDto.setApiSecret(secret);
            apiKeyRespDto.setIssuerId(issuerPrivateKeyManager.getEncAddress());
            dataResp.setData(apiKeyRespDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("platform init error {}", e);
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }

    private String getPTCInput(AbstractCrossChainCertificate certificate) {
        String args = "'" + certificate.getId() + "','" + Base64.encode(certificate.encode()) + "'";
        return "{\"function\":\"addCertificate(string,bytes)\",\"args\":\""+ args+"\"}";

    }

    private String getRelayInput(AbstractCrossChainCertificate certificate) {
        //RelayerCredentialSubject relayerCredentialSubject = RelayerCredentialSubject.decode(certificate.getCredentialSubject());
        //todo 通过公钥构造地址
//        ObjectIdentity objectIdentity = relayerCredentialSubject.getApplicant();
//        String relayAddress = new String(objectIdentity.getRawId());
        //byte[] publicKey = relayerCredentialSubject.getRawSubjectPublicKey();
        //String publicKeyStr2 = new String(publicKey);
        //PublicKeyManager publicKeyManager = new PublicKeyManager(publicKeyStr2);
        String relayAddress = BIDHelper.encAddress(BIDHelper.getKeyTypeFromPublicKey(CrossChainCertificateUtil.getPublicKeyFromCrossChainCertificate(certificate)),
                CrossChainCertificateUtil.getRawPublicKeyFromCrossChainCertificate(certificate));
        String args = "'" + certificate.getId() + "','" + Base64.encode(certificate.encode()) + "'," + relayAddress;
        return "{\"function\":\"addCertificate(string,bytes,address)\",\"args\":\""+ args +"\"}";
    }

    private String getDomainNameInput(AbstractCrossChainCertificate certificate) {
        DomainNameCredentialSubject domainNameCredentialSubject = DomainNameCredentialSubject.decode(certificate.getCredentialSubject());
        CrossChainDomain crossChainDomain = domainNameCredentialSubject.getDomainName();
        String args = "'" + certificate.getId() + "','" + crossChainDomain.getDomain() + "','" + Base64.encode(certificate.encode()) + "'";
        return "{\"function\":\"addCertificate(string,string,bytes)\",\"args\":\""+ args+"\"}";
    }

    private String auditTxSubmit(AbstractCrossChainCertificate certificate, String issuerPrivateKey, String issuerId, VcRecordDomain domain) {
        byte credentialType = domain.getCredentialType().byteValue();
        String targetContract = "";
        String input = "";
        switch (CrossChainCertificateTypeEnum.valueOf(credentialType)) {
            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                targetContract = ptcContractAddress;
                input = getPTCInput(certificate);
                break;
            case RELAYER_CERTIFICATE:
                targetContract = relayContractAddress;
                input = getRelayInput(certificate);
                break;
            case DOMAIN_NAME_CERTIFICATE:
                targetContract = domainNameContractAddress;
                input = getDomainNameInput(certificate);
                break;
            default:
                logger.error("templateId error");
                break;
        }

        if (targetContract.isEmpty()) throw new APIException(ExceptionEnum.PARAME_ERROR);

        //todo method
        BIFContractInvokeRequest request = new BIFContractInvokeRequest();
        request.setSenderAddress(issuerId);
        request.setPrivateKey(issuerPrivateKey);
        request.setContractAddress(targetContract);
        request.setBIFAmount(0L);
        request.setGasPrice(1L);
        request.setRemarks("contract invoke");
        request.setInput(input);
        request.setFeeLimit(20000000L);


        String txHash = "";
        BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
        BIFContractInvokeResponse response = sdk.getBIFContractService().contractInvoke(request);
        if(ExceptionEnum.SUCCESS.getErrorCode().equals(response.getErrorCode())){
            txHash = response.getResult().getHash();
        }else {
            throw new APIException(ExceptionEnum.PARAME_ERROR);
        }
        return txHash;
    }


    private AbstractCrossChainCertificate createVc(String issuerPrivateKey, String issuerId, VcRecordDomain domain, String vcId) {
        //create root vc
        AbstractCrossChainCertificate abstractCrossChainCertificate = null;
        Integer credentialType = domain.getCredentialType();
        switch (CrossChainCertificateTypeEnum.valueOf(credentialType.byteValue())) {
            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                abstractCrossChainCertificate = vcProtocolService.buildPTCVc(issuerPrivateKey, issuerId, vcId, domain);
                break;
            case RELAYER_CERTIFICATE:
                abstractCrossChainCertificate = vcProtocolService.buildRelayVc(issuerPrivateKey, issuerId, vcId, domain);
                break;
            case DOMAIN_NAME_CERTIFICATE:
                abstractCrossChainCertificate = vcProtocolService.buildDomainNameVc(issuerPrivateKey, issuerId, vcId, domain);
                break;
            default:
                break;
        }

        return abstractCrossChainCertificate;
    }
    private byte[] getVcOwnerId(VcRecordDomain domain) {
        byte[] vcOwnerId = null;
        Integer credentialType = domain.getCredentialType();
        AbstractCrossChainCertificate cert = CrossChainCertificateFactory.createCrossChainCertificate(domain.getContent());
        switch (CrossChainCertificateTypeEnum.valueOf(credentialType.byteValue())) {
            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                PTCCredentialSubject ptcCredentialSubject = PTCCredentialSubject.decode(cert.getCredentialSubject());
                vcOwnerId = ptcCredentialSubject.getApplicant().encode();
                break;
            case RELAYER_CERTIFICATE:
                RelayerCredentialSubject relayerCredentialSubject = RelayerCredentialSubject.decode(cert.getCredentialSubject());
                vcOwnerId = relayerCredentialSubject.getApplicant().encode();
                break;
            case DOMAIN_NAME_CERTIFICATE:
                DomainNameCredentialSubject domainNameCredentialSubject = DomainNameCredentialSubject.decode(cert.getCredentialSubject());
                vcOwnerId = domainNameCredentialSubject.getApplicant().encode();
                break;
            default:
                break;
        }
        return vcOwnerId;
    }

    public DataResp<VcIssueAuditRespDto> vcAudit(String accessToken, VcIssueAuditReqDto vcIssueAuditReqDto) {
        DataResp<VcIssueAuditRespDto> vcIssusAuditRespDtoDataResp = new DataResp<VcIssueAuditRespDto>();
        try {
            //check access token
            Map<String, String> paramMap = JwtUtil.decode(accessToken);
            if (paramMap == null) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            String issuerId = paramMap.get(Constants.ISSUER_ID);
            String token = redisUtil.get(issuerId);
            if (!token.equals(accessToken)) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            //deal request
            String applyNo = vcIssueAuditReqDto.getApplyNo();
            Integer status = vcIssueAuditReqDto.getStatus();
            String reason = vcIssueAuditReqDto.getReason();

            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord(applyNo);
            if (Tools.isNull(vcRecordDomain)) throw new APIException(ExceptionEnum.CREDENTIAL_APPLY_NOT_EXIST);
            if (!Tools.isNull(vcRecordDomain) && !StatusEnum.APPLYING.getCode().equals(vcRecordDomain.getStatus())) {
                throw new APIException(ExceptionEnum.CREDENTIAL_AUDITED);
            }

            VcAuditDomain vcAuditDomain = new VcAuditDomain();
            VcIssueAuditRespDto vcIssueAuditRespDto = new VcIssueAuditRespDto();
            String txHash = "";
            String vcId = "";
            AbstractCrossChainCertificate abstractCrossChainCertificate = null;
            if (StatusEnum.AUDIT_PASS.getCode().equals(status)) {
                ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyDomain(1);
                String issuerPrivateKey = apiKeyDomain.getIssuerPrivateKey();
                //create vc
                KeyPairEntity keyPairEntity = KeyPairEntity.getBidAndKeyPair();
                vcId = keyPairEntity.getEncAddress();
                abstractCrossChainCertificate = createVc(issuerPrivateKey, issuerId, vcRecordDomain, vcId);
                if (Tools.isNull(abstractCrossChainCertificate)) {
                    throw new APIException(ExceptionEnum.CREDENTIAL_BUILD_ERROR);
                }
                //submit to on-chain
                txHash = auditTxSubmit(abstractCrossChainCertificate, issuerPrivateKey, issuerId, vcRecordDomain);
                if (txHash.isEmpty()) {
                    throw new APIException(ExceptionEnum.SUBMIT_TX_ERROR);
                }
                vcAuditDomain.setVcId(vcId);
                byte[] vcOwnerId = getVcOwnerId(vcRecordDomain);
                vcAuditDomain.setVcOwnerId(vcOwnerId);
                vcAuditDomain.setReason(reason);
            } else if (StatusEnum.AUDIT_REJECT.getCode().equals(status)) {
                vcAuditDomain.setReason(reason);
            } else {
                throw new APIException(ExceptionEnum.PARAME_ERROR);
            }

            ObjectIdentity objectIdentity = new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes());
            vcAuditDomain.setApplyNo(applyNo);
            vcAuditDomain.setAuditId(objectIdentity.encode());
            vcAuditDomain.setStatus(status);
            vcAuditDomain.setCreateTime(DateUtil.currentSeconds());

            byte[] vcData = Tools.isNull(abstractCrossChainCertificate) ? null : abstractCrossChainCertificate.encode();
            vcAuditService.insertAudit(vcAuditDomain);
            vcRecordDomain.setStatus(status);
            vcRecordDomain.setVcId(vcId);
            vcRecordDomain.setVcData(vcData);
            vcRecordDomain.setUpdateTime(DateUtil.currentSeconds());
            vcRecordService.updateAuditPassStatus(vcRecordDomain);
            vcIssueAuditRespDto.setTxHash(txHash);
            vcIssusAuditRespDtoDataResp.setData(vcIssueAuditRespDto);
            vcIssusAuditRespDtoDataResp.buildSuccessField();
        } catch (APIException e) {
            vcIssusAuditRespDtoDataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("审核异常", e);
            vcIssusAuditRespDtoDataResp.buildSysExceptionField();
        }
        return vcIssusAuditRespDtoDataResp;
    }

    public DataResp<VcApplyListRespDto> queryList(VcApplyListReqDto reqDto) {
        DataResp<VcApplyListRespDto> dataResp = new DataResp<VcApplyListRespDto>();
        try {
            reqDto.setStartNum((reqDto.getPageStart() - 1) * reqDto.getPageSize());
            if(reqDto.getStatus() != null && reqDto.getStatus().length == 0) {
                reqDto.setStatus(null);
            }
            List<VcRecordListDomain> vcRecordDomain = vcRecordService.queryList(reqDto);
            List<VcApplyListRespDto.IssueListDTO> issueListDTOList = buildVcList(vcRecordDomain);
            int total = vcRecordService.queryListCount(reqDto);
            VcApplyListRespDto respDto = new VcApplyListRespDto();
            respDto.setDataList(issueListDTOList);
            respDto.getPage().setPageSize(reqDto.getPageSize());
            respDto.getPage().setPageStart(reqDto.getPageStart());
            respDto.getPage().setPageTotal(total);
            dataResp.setData(respDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("credential issue list error:{}", e);
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }

    private List<VcApplyListRespDto.IssueListDTO> buildVcList(List<VcRecordListDomain> vcRecordDomain) {
        ArrayList<VcApplyListRespDto.IssueListDTO> issueListDTOList = new ArrayList<>();
        for (VcRecordListDomain vcr : vcRecordDomain) {
            VcApplyListRespDto.IssueListDTO dto = new VcApplyListRespDto.IssueListDTO();
            BeanUtils.copyProperties(vcr, dto);
            dto.setCreateTime(vcr.getCreateTime());
            dto.setAuditTime(vcr.getAuditTime());
            issueListDTOList.add(dto);
        }
        return issueListDTOList;
    }

    public DataResp<VcApplyDetailRespDto> queryDetail(VcApplyDetailReqDto reqDto) {
        DataResp<VcApplyDetailRespDto> dataResp = new DataResp<VcApplyDetailRespDto>();
        try {
            VcRecordDomain vcRecordDomain = vcRecordService.queryDetail(reqDto);
            if(!Tools.isNull(vcRecordDomain)){
                VcApplyDetailRespDto dto = new VcApplyDetailRespDto();
                if(!vcRecordDomain.getStatus().equals(CredentialApplyStatusEnum.T1.getCode())){
                    VcAuditDomain vcAuditDomain = vcAuditService.getAuditDomain(vcRecordDomain.getApplyNo());
                    if(!Tools.isNull(vcAuditDomain)){
                        dto.setAuditId(vcAuditDomain.getAuditId());
                        dto.setAuditTime(vcAuditDomain.getCreateTime());
                        dto.setAuditRemark(vcAuditDomain.getReason());
                    }
                }

                dto.setApplyNo(vcRecordDomain.getApplyNo());
                dto.setApplyTime(vcRecordDomain.getCreateTime() != null ? vcRecordDomain.getCreateTime() : null);
                dto.setStatus(vcRecordDomain.getStatus().toString());
                dto.setContent(vcRecordDomain.getContent());
                dto.setApplyUser(vcRecordDomain.getUserId());
                dataResp.setData(dto);
                dataResp.buildSuccessField();
            }else{
                dataResp.buildCommonField(ExceptionEnum.CREDENTIAL_APPLY_NOT_EXIST.getErrorCode(), ExceptionEnum.CREDENTIAL_APPLY_NOT_EXIST.getMessage());
            }
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("credential issue list error:{}", e);
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }

    public DataResp<VcIssueRespDto> vcIssue(VcIssueReqDto requestBody) {
        DataResp<VcIssueRespDto> dataResp = new DataResp<VcIssueRespDto>();
        try {

        }catch (APIException e){
            dataResp.buildAPIExceptionField(e);
        }catch (Exception e){
            logger.error("issue vc", e);
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }

    private String revokeTxSubmit(String credentialId, Integer credentialType, String issuerPrivateKey, String issuerId) {
        String targetContract = "";
        String input = "{\"function\":\"revokeCertificate(string)\",\"args\":\"'"+ credentialId+"'\"}";
        switch (CrossChainCertificateTypeEnum.valueOf(credentialType.byteValue())) {
            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                targetContract = ptcContractAddress;
                break;
            case RELAYER_CERTIFICATE:
                targetContract = relayContractAddress;
                break;
            case DOMAIN_NAME_CERTIFICATE:
                targetContract = domainNameContractAddress;
                break;
            default:
                logger.error("templateId error");
                break;
        }

        if (targetContract.isEmpty()) throw new APIException(ExceptionEnum.PARAME_ERROR);

        BIFContractInvokeRequest request = new BIFContractInvokeRequest();
        request.setSenderAddress(issuerId);
        request.setPrivateKey(issuerPrivateKey);
        request.setContractAddress(targetContract);
        request.setBIFAmount(0L);
        request.setGasPrice(1L);
        request.setRemarks("contract invoke");
        request.setInput(input);
        request.setFeeLimit(20000000L);

        String txHash = "";
        BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
        BIFContractInvokeResponse response = sdk.getBIFContractService().contractInvoke(request);
        if(ExceptionEnum.SUCCESS.getErrorCode().equals(response.getErrorCode())){
            txHash = response.getResult().getHash();
        }else {
            throw new APIException(ExceptionEnum.PARAME_ERROR);
        }
        return txHash;
    }

    public DataResp<VcRevocationRespDto> revocationVc(String accessToken, VcRevocationReqDto reqDto) {
        DataResp<VcRevocationRespDto> dataResp = new DataResp<VcRevocationRespDto>();
        try {
            //check access token
            Map<String,String> paramMap = JwtUtil.decode(accessToken);
            if (paramMap == null) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            String issuerId = paramMap.get(Constants.ISSUER_ID);
            String token = redisUtil.get(issuerId);
            if (!token.equals(accessToken)) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            //todo
            String credentialId = reqDto.getCredentialId();
            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(credentialId);
            VcRevocationRespDto respDto = new VcRevocationRespDto();
            String txHash = "";
            if (Tools.isNull(vcRecordDomain)) {
                throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
            } else {
                ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyDomain(1);
                String issuerPrivateKey = apiKeyDomain.getIssuerPrivateKey();

                txHash = revokeTxSubmit(credentialId, vcRecordDomain.getCredentialType(), issuerPrivateKey, issuerId);
                if (txHash.isEmpty()) {
                    throw new APIException(ExceptionEnum.SUBMIT_TX_ERROR);
                }
                vcRecordDomain.setStatus(StatusEnum.REVOKE.getCode());
                vcRecordDomain.setUpdateTime(DateUtil.currentSeconds());
                vcRecordService.updateRevokeStatus(vcRecordDomain);
            }
            respDto.setTxHash(txHash);
            dataResp.setData(respDto);
            dataResp.buildSuccessField();
        }catch (APIException e){
            dataResp.buildAPIExceptionField(e);
        }catch (Exception e){
            logger.error("get root vc", e);
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }
}

