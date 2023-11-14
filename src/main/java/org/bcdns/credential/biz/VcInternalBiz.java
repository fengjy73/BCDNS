package org.bcdns.credential.biz;


import cn.ac.caict.bid.model.BIDDocumentOperation;
import cn.ac.caict.bid.model.BIDpublicKeyOperation;
import cn.bif.model.crypto.KeyPairEntity;
import cn.bif.module.encryption.key.PrivateKeyManager;
import cn.hutool.core.date.DateUtil;
import cn.hutool.crypto.digest.SM3;
import com.alibaba.fastjson.JSONObject;
import com.alipay.antchain.bridge.commons.bcdns.*;
import com.alipay.antchain.bridge.commons.core.base.BIDInfoObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentityType;
import com.alipay.antchain.bridge.commons.exception.AntChainBridgeCommonsException;
import com.alipay.antchain.bridge.commons.exception.CommonsErrorCodeEnum;
import org.bcdns.credential.common.constant.Constants;
import org.bcdns.credential.common.utils.AppUtils;
import org.bcdns.credential.common.utils.JwtUtil;
import org.bcdns.credential.common.utils.RedisUtil;
import org.bcdns.credential.common.utils.Tools;
import org.bcdns.credential.dao.domain.*;
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

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;


@Component
public class VcInternalBiz {

    @Value("${object-identity.supernode.x509-private-key}")
    private String superNodeX509PrivateKey;

    @Value("${object-identity.supernode.x509-public-key}")
    private String superNodeX509PublicKey;

    @Value("${object-identity.issuer.x509-private-key}")
    private String issuerX509PrivateKey;

    @Value("${object-identity.issuer.x509-public-key}")
    private String issuerX509PublicKey;

    @Value("${object-identity.supernode.bid-private-key}")
    private String superNodeBidPrivateKey;

    @Value("${object-identity.issuer.bid-private-key}")
    private String issuerBidPrivateKey;

    @Value("${object-identity-type}")
    private Integer objectIdentityType;

    @Value("${sign-type}")
    private String signAlg;

    @Value("${ptc.contract.address}")
    private String ptcContractAddress;

    @Value("${relay.contract.address}")
    private String relayContractAddress;

    @Value("${domain-name.contract.address}")
    private String domainNameContractAddress;

    @Value("${sdk.url}")
    private String sdkUrl;

    private static final Logger logger = LoggerFactory.getLogger(VcInternalBiz.class);

    @Resource
    private ApiKeyService apiKeyService;
    @Resource
    private VcRecordService vcRecordService;
    @Resource
    private VcAuditService vcAuditService;
    @Resource
    private VcProtocolService vcProtocolService;
    @Resource
    private RedisUtil redisUtil;
    @Resource
    private VcRootService vcRootService;

    @Autowired
    private DistributedLock distributedLock;

    public DataResp<ApiKeyRespDto> init() {
        DataResp<ApiKeyRespDto> dataResp = new DataResp<ApiKeyRespDto>();
        try {
            ObjectIdentityType type = ObjectIdentityType.parseFromValue(objectIdentityType);
            switch (type) {
                case X509_PUBLIC_KEY_INFO:
                    dataResp = x509TypeInit();
                    break;
                case BID:
                    dataResp = bidTypeInit();
                    break;
                default:
                    throw new AntChainBridgeCommonsException(CommonsErrorCodeEnum.BCDNS_OID_UNSUPPORTED_TYPE, "BCDNS unsupported oid type: " + objectIdentityType);
            }
        } catch (AntChainBridgeCommonsException e) {
            dataResp.buildAntChainBridgeCommonsExceptionField(e);
        } catch (Exception e) {
            logger.error("platform init error {}", e);
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }
    private DataResp<ApiKeyRespDto> x509TypeInit() {
        DataResp<ApiKeyRespDto> dataResp = new DataResp<ApiKeyRespDto>();
        try {

        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("x509 type platform init error:{}", e);
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }

    private DataResp<ApiKeyRespDto> bidTypeInit() {
        DataResp<ApiKeyRespDto> dataResp = new DataResp<ApiKeyRespDto>();
        PrivateKeyManager superNodePrivateKeyManager = new PrivateKeyManager(superNodeBidPrivateKey);
        PrivateKeyManager issuerPrivateKeyManager = new PrivateKeyManager(issuerBidPrivateKey);
        try {
            ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyDomain(1);
            if (!Tools.isNull(apiKeyDomain) && apiKeyDomain.getInitTag().equals(1)) {
                throw new APIException(ExceptionEnum.PLATFORM_REPEAT_INIT);
            }

            //create root vc
            //context
            String context = "https://www.w3.org/2018/credentials/v1";
            //bid document info
            BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[2];
            biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
            biDpublicKeyOperation[0].setPublicKeyHex(issuerPrivateKeyManager.getEncPublicKey());
            BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
            bidDocumentOperation.setPublicKey(biDpublicKeyOperation);
            BIDInfoObjectIdentity bidInfoObjectIdentity = new BIDInfoObjectIdentity(bidDocumentOperation);

            ObjectIdentity rootObjectIdentity = new ObjectIdentity(ObjectIdentityType.BID, issuerPrivateKeyManager.getEncAddress().getBytes());
            AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                    context,
                    CrossChainCertificateV1.MY_VERSION,
                    KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                    new ObjectIdentity(ObjectIdentityType.BID, superNodePrivateKeyManager.getEncAddress().getBytes()),
                    DateUtil.currentSeconds(),
                    DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                    new BCDNSTrustRootCredentialSubject(
                            "root_verifiable_credential",
                            rootObjectIdentity,
                            bidInfoObjectIdentity.encode()
                    )
            );

            byte[] msg = certificate.getEncodedToSign();
            byte[] sign = superNodePrivateKeyManager.sign(msg);
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
            apiKeyDomain1.setIssuerId(rootObjectIdentity.encode());
            apiKeyDomain1.setInitTag(1);
            apiKeyService.insert(apiKeyDomain1);

            ApiKeyRespDto apiKeyRespDto = new ApiKeyRespDto();
            apiKeyRespDto.setApiKey(apiKey);
            apiKeyRespDto.setApiSecret(secret);
            apiKeyRespDto.setIssuerId(rootObjectIdentity);
            dataResp.setData(apiKeyRespDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("bid type platform init error:{}", e);
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }

    private String auditTxSubmit(String certificate, String issuerPrivateKey, String issuerId, VcRecordDomain domain) {
        return "success";
        //todo contract
//        byte credentialType = domain.getCredentialType();
//        String targetContract = "";
//        switch (CrossChainCertificateTypeEnum.valueOf(credentialType)) {
//            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
//                targetContract = ptcContractAddress;
//                break;
//            case RELAYER_CERTIFICATE:
//                targetContract = relayContractAddress;
//                break;
//            case DOMAIN_NAME_CERTIFICATE:
//                targetContract = domainNameContractAddress;
//                break;
//            default:
//                logger.error("templateId error");
//                break;
//        }
//
//        if (targetContract.isEmpty()) throw new APIException(ExceptionEnum.PARAME_ERROR);
//
//        BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
//        //todo method
//        JSONObject params = new JSONObject();
//        params.put("certificate", certificate);
//        JSONObject input = new JSONObject();
//        input.put("method", "put");
//        input.put("params", params);
//        long amount = 0L;
//
//        BIFContractInvokeRequest bifContractInvokeRequest = new BIFContractInvokeRequest();
//        bifContractInvokeRequest.setSenderAddress(issuerId);
//        bifContractInvokeRequest.setContractAddress(targetContract);
//        bifContractInvokeRequest.setBIFAmount(amount);
//        bifContractInvokeRequest.setPrivateKey(issuerPrivateKey);
//        bifContractInvokeRequest.setRemarks("put certificate");
//
//        String txHash = "";
//        BIFContractInvokeResponse response = sdk.getBIFContractService().contractInvoke(bifContractInvokeRequest);
//        if(ExceptionEnum.SUCCESS.getErrorCode().equals(response.getErrorCode())){
//            txHash = response.getResult().getHash();
//        }else {
//            throw new APIException(ExceptionEnum.PARAME_ERROR);
//        }
//        return txHash;
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
        switch (CrossChainCertificateTypeEnum.valueOf(credentialType.byteValue())) {
            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                PTCContentEntity ptcContentEntity = PTCContentEntity.decode(domain.getContent());
                vcOwnerId = ptcContentEntity.getApplicant().encode();
                break;
            case RELAYER_CERTIFICATE:
                RelayContentEntity relayContentEntity = RelayContentEntity.decode(domain.getContent());
                vcOwnerId = relayContentEntity.getApplicant().encode();
                break;
            case DOMAIN_NAME_CERTIFICATE:
                DomainNameContentEntity domainNameContentEntity = DomainNameContentEntity.decode(domain.getContent());
                vcOwnerId = domainNameContentEntity.getApplicant().encode();
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
                String certificate = JSONObject.toJSONString(abstractCrossChainCertificate);
                //submit to on-chain
                txHash = auditTxSubmit(certificate, issuerPrivateKey, issuerId, vcRecordDomain);
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

            ObjectIdentity objectIdentity = new ObjectIdentity(ObjectIdentityType.parseFromValue(objectIdentityType), issuerId.getBytes());
            vcAuditDomain.setApplyNo(applyNo);
            vcAuditDomain.setAuditId(objectIdentity.encode());
            vcAuditDomain.setStatus(status);
            vcAuditDomain.setCreateTime(DateUtil.currentSeconds());

            byte[] vcData = Tools.isNull(abstractCrossChainCertificate) ? null : abstractCrossChainCertificate.encode();
            vcAuditService.insertAudit(vcAuditDomain);
            vcRecordService.updateAuditPassStatus(applyNo, status, vcId, vcData, DateUtil.currentSeconds());
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

    private String revokeTxSubmit(String credentialId, String issuerPrivateKey, String issuerId) {
        return "success";
        //todo contract
//        byte credentialType = domain.getCredentialType();
//        String targetContract = "";
//        switch (CrossChainCertificateTypeEnum.valueOf(credentialType)) {
//            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
//                targetContract = ptcContractAddress;
//                break;
//            case RELAYER_CERTIFICATE:
//                targetContract = relayContractAddress;
//                break;
//            case DOMAIN_NAME_CERTIFICATE:
//                targetContract = domainNameContractAddress;
//                break;
//            default:
//                logger.error("templateId error");
//                break;
//        }
//
//        if (targetContract.isEmpty()) throw new APIException(ExceptionEnum.PARAME_ERROR);
//
//        BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
//        //todo method
//        JSONObject params = new JSONObject();
//        params.put("certificate", certificate);
//        JSONObject input = new JSONObject();
//        input.put("method", "put");
//        input.put("params", params);
//        long amount = 0L;
//
//        BIFContractInvokeRequest bifContractInvokeRequest = new BIFContractInvokeRequest();
//        bifContractInvokeRequest.setSenderAddress(issuerId);
//        bifContractInvokeRequest.setContractAddress(targetContract);
//        bifContractInvokeRequest.setBIFAmount(amount);
//        bifContractInvokeRequest.setPrivateKey(issuerPrivateKey);
//        bifContractInvokeRequest.setRemarks("put certificate");
//
//        String txHash = "";
//        BIFContractInvokeResponse response = sdk.getBIFContractService().contractInvoke(bifContractInvokeRequest);
//        if(ExceptionEnum.SUCCESS.getErrorCode().equals(response.getErrorCode())){
//            txHash = response.getResult().getHash();
//        }else {
//            throw new APIException(ExceptionEnum.PARAME_ERROR);
//        }
//        return txHash;
    }

    public DataResp<VcRevocationRespDto> revocationVc(String accessToken, VcRevocationReqDto reqDto) {
        DataResp<VcRevocationRespDto> dataResp = new DataResp<VcRevocationRespDto>();
        try {
            //check access token
            Map<String,String> paramMap = JwtUtil.decode(accessToken);
            if (paramMap == null) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            String managerId = paramMap.get("managerId");
            String token = redisUtil.get(managerId);
            if (!token.equals(accessToken)) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }
            //todo
            String credentialId = reqDto.getCredentialId();
            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(credentialId);
            VcRevocationRespDto respDto = new VcRevocationRespDto();
            String txHash = "";
            if(Tools.isNull(vcRecordDomain)){
                throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
            } else {
                ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyDomain(1);
                String issuerPrivateKey = apiKeyDomain.getIssuerPrivateKey();

                txHash = revokeTxSubmit(credentialId, issuerPrivateKey, managerId);
                if (txHash.isEmpty()) {
                    throw new APIException(ExceptionEnum.SUBMIT_TX_ERROR);
                }
                vcRecordService.updateRevokeStatus(credentialId, StatusEnum.REVOKE.getCode(), DateUtil.currentSeconds());
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

