package org.bcdns.credential.biz;


import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import cn.bif.api.BIFSDK;
import cn.bif.model.request.BIFContractCallRequest;
import cn.bif.model.request.BIFContractInvokeRequest;
import cn.bif.model.response.BIFContractCallResponse;
import cn.bif.model.response.BIFContractInvokeResponse;
import cn.bif.module.contract.BIFContractService;
import cn.bif.module.encryption.key.PrivateKeyManager;
import cn.bif.module.encryption.key.PublicKeyManager;
import cn.bif.utils.base.Base58;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import com.alibaba.druid.filter.config.ConfigTools;
import com.alibaba.fastjson.JSONObject;
import com.alipay.antchain.bridge.commons.bcdns.AbstractCrossChainCertificate;
import com.alipay.antchain.bridge.commons.bcdns.CrossChainCertificateFactory;
import com.alipay.antchain.bridge.commons.bcdns.CrossChainCertificateTypeEnum;
import com.alipay.antchain.bridge.commons.bcdns.utils.CrossChainCertificateUtil;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.X509PubkeyInfoObjectIdentity;
import com.alipay.antchain.bridge.commons.core.ptc.PTCTrustRoot;
import com.alipay.antchain.bridge.commons.core.ptc.ThirdPartyBlockchainTrustAnchor;
import com.alipay.antchain.bridge.commons.exception.AntChainBridgeCommonsException;
import com.alipay.antchain.bridge.commons.exception.CommonsErrorCodeEnum;
import com.alipay.antchain.bridge.commons.utils.crypto.HashAlgoEnum;
import com.alipay.antchain.bridge.commons.utils.crypto.SignAlgoEnum;
import org.bcdns.credential.common.constant.Constants;
import org.bcdns.credential.common.utils.IdGenerator;
import org.bcdns.credential.common.utils.RedisUtil;
import org.bcdns.credential.common.utils.Tools;
import org.bcdns.credential.dto.req.*;
import org.bcdns.credential.dto.resp.*;
import org.bcdns.credential.enums.ExceptionEnum;
import org.bcdns.credential.enums.StatusEnum;
import org.bcdns.credential.exception.APIException;
import org.bcdns.credential.model.ApiKeyDomain;
import org.bcdns.credential.model.VcAuditDomain;
import org.bcdns.credential.model.VcRecordDomain;
import org.bcdns.credential.model.VcRootDomain;
import org.bcdns.credential.service.ApiKeyService;
import org.bcdns.credential.service.VcAuditService;
import org.bcdns.credential.service.VcRecordService;
import org.bcdns.credential.service.VcRootService;
import org.bcdns.credential.utils.DistributedLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


@Component
public class VcExternalBiz {

    @Value("${object-identity.supernode.bid-private-key}")
    private String superNodeBidPrivateKey;

    @Value("${object-identity.issuer.bid-private-key}")
    private String issuerBidPrivateKey;

    @Value("${dpos.contract.address}")
    private String dposContractAddress;

    @Value("${ptc.contract.address}")
    private String ptcContractAddress;

    @Value("${relay.contract.address}")
    private String relayContractAddress;

    @Value("${ptc-trust-root.contract.address}")
    private String ptcTrustRootContractAddress;

    @Value("${tpbta.contract.address}")
    private String tpbtaContractAddress;

    @Value("${issue.decrypt.public-key}")
    private String decryptPublicKey;

    @Autowired
    private ApiKeyService apiKeyService;

    @Value("${run.type}")
    private int runType;

    private static final Logger logger = LoggerFactory.getLogger(VcExternalBiz.class);

    @Autowired
    private VcRecordService vcRecordService;

    @Autowired
    private VcRootService vcRootService;

    @Autowired
    private VcAuditService vcAuditService;

    @Autowired
    private DistributedLock distributedLock;

    @Autowired
    private RedisUtil redisUtil;

    @Value("${sdk.url}")
    private String sdkUrl;

    /*@Value("${owner.address}")
    private String ownerAddress;

    @Value("${owner.private-key}")
    private String ownerPrivateKey;*/

    private static final String GET_CERT_BY_ID
            = "{\"function\":\"getCertById(string)\",\"args\":\"'{}'\",\"return\":\"returns(bytes)\"}";

    private static final String GET_PTCTRUSTROOT_BY_ID
            = "{\"function\":\"getPTCTrustRootById(bytes32)\",\"args\":\"'{}'\",\"return\":\"returns(bytes)\"}";

    private static final String ADD_PTCTRUSTROOT_BY_PTCOID_TEMPLATE
            = "{\"function\":\"addPTCTR(bytes32,bytes)\",\"args\":\"'{}','{}'\"}";

    private static final String UPGRADE_PTCTRUSTROOT_BY_PTCOID_TEMPLATE
            = "{\"function\":\"upgradePTCTR(bytes32,bytes)\",\"args\":\"'{}','{}'\"}";

    private static final String BINDING_DOMAIN_NAME_WITH_TPBTA_TEMPLATE
            = "{\"function\":\"bindingDomainNameWithTPBTA(string,bytes)\",\"args\":\"'{}','{}'\"}";

    private static final String GET_TPBTA_BY_LANE
            = "{\"function\":\"getTPBTAByLane(string,uint16)\",\"args\":\"'{}',{}\",\"return\":\"returns(bytes)\"}";

    private static final String GET_TPBTA_LATEST_VERSION_BY_LANE
            = "{\"function\":\"getTPBTALatestVersionByLane(string)\",\"args\":\"'{}'\",\"return\":\"returns(uint16)\"}";

    private static final String ADD_TPBTA_BY_LANE
            = "{\"function\":\"addTPBTA(string,uint16,bytes)\",\"args\":\"'{}',{},'{}'\"}";

    private void isBackbone(String publicKey) throws Exception {
        try {
            PublicKeyManager publicKeyManager = new PublicKeyManager(publicKey);
            BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
            String input = StrUtil.format("{\"method\":\"getnodeinfo\",\"params\":{\"address\":\"{}\"}}", publicKeyManager.getEncAddress());
            BIFContractCallRequest bifContractCallRequest = new BIFContractCallRequest();
            bifContractCallRequest.setInput(input);
            bifContractCallRequest.setContractAddress(dposContractAddress);
            BIFContractService contractService = sdk.getBIFContractService();
            BIFContractCallResponse callResp = contractService.contractQuery(bifContractCallRequest);
            if (ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())) {
                if (((HashMap<String, Object>) callResp.getResult().getQueryRets().get(0)).containsKey("result")) {
                    JSONObject result = JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result");
                    String roleType = result.getJSONObject("data").getJSONObject("nodeInfo").getString("roleType");
                    if (!"backbone".equals(roleType) && !"super".equals(roleType) && !"validator".equals(roleType)) {
                        throw new APIException(ExceptionEnum.SYS_ERROR, "check is not backbone node");
                    }
                } else {
                    throw new APIException(ExceptionEnum.SYS_ERROR, "failed to query dpos node information");
                }
            } else {
                throw new APIException(ExceptionEnum.SYS_ERROR, "failed to query dpos contract");
            }
        } catch (Exception e) {
            throw new APIException(String.format("failed to check backbone node: %s", publicKey), e);
        }
    }

    private void isSuperNode(String publicKey) throws Exception {
        try {
            PublicKeyManager publicKeyManager = new PublicKeyManager(publicKey);
            BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
            String input = StrUtil.format("{\"method\":\"getnodeinfo\",\"params\":{\"address\":\"{}\"}}", publicKeyManager.getEncAddress());
            BIFContractCallRequest bifContractCallRequest = new BIFContractCallRequest();
            bifContractCallRequest.setInput(input);
            bifContractCallRequest.setContractAddress(dposContractAddress);
            BIFContractService contractService = sdk.getBIFContractService();
            BIFContractCallResponse callResp = contractService.contractQuery(bifContractCallRequest);
            if (ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())) {
                if (((HashMap<String, Object>) callResp.getResult().getQueryRets().get(0)).containsKey("result")) {
                    JSONObject result = JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result");
                    String roleType = result.getJSONObject("data").getJSONObject("nodeInfo").getString("roleType");
                    if (!"super".equals(roleType) && !"validator".equals(roleType)) {
                        throw new APIException(ExceptionEnum.SYS_ERROR, "check is not super node");
                    }
                } else {
                    throw new APIException(ExceptionEnum.SYS_ERROR, "failed to query dpos node information");
                }
            } else {
                throw new APIException(ExceptionEnum.SYS_ERROR, "failed to query dpos contract");
            }
        } catch (Exception e) {
            throw new APIException(String.format("failed to check super node: %s", publicKey), e);
        }
    }

    private void isRelayer(String publicKey) throws Exception {
        ObjectIdentity objectIdentity = new X509PubkeyInfoObjectIdentity(Base64.decode(publicKey));
        VcAuditDomain vcAuditDomain = vcAuditService.getVcIdByVcOwner(objectIdentity.encode());
        if (Tools.isNull(vcAuditDomain)) {
            throw new APIException(ExceptionEnum.SYS_ERROR, "check relay error, credential is not exist");
        }

        VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(vcAuditDomain.getVcId());
        if (Tools.isNull(vcRecordDomain)) {
            throw new APIException(ExceptionEnum.SYS_ERROR, "check relay error, credential is not exist");
        }
        if (!vcRecordDomain.getCredentialType().equals(3)) {
            throw new APIException(ExceptionEnum.SYS_ERROR, "check relay error, credential type is not relay");
        }
        if (vcRecordDomain.getStatus().equals(StatusEnum.REVOKE.getCode())) {
            throw new APIException(ExceptionEnum.SYS_ERROR, "check relay error, credential has revoked");
        }
    }

    private void checkVcApply(String publicKey, String signAlgo, VcApplyReqDto vcApplyReqDto) throws Exception {
        //sign verify
        byte[] sign = vcApplyReqDto.getSign(); //clientCredential.signAuthorizedRequest(certSigningRequest.getEncodedToSign())
        byte[] content = vcApplyReqDto.getContent(); //AbstractCrossChainCertificate certSigningRequest
        boolean verifyResult;

        AbstractCrossChainCertificate crossChainCertificate = CrossChainCertificateFactory.createCrossChainCertificate(content);
        if (crossChainCertificate.getType() == CrossChainCertificateTypeEnum.RELAYER_CERTIFICATE
                || crossChainCertificate.getType() == CrossChainCertificateTypeEnum.PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE) {
            verifyResult = PublicKeyManager.verify(content, sign, publicKey);
        } else {
            // MARK
            verifyResult = SignAlgoEnum.getByName(signAlgo).getSigner().verify(
                    new X509PubkeyInfoObjectIdentity(Base64.decode(publicKey)).getPublicKey(),
                    content,
                    sign
            );
        }
        if (!verifyResult) {
            throw new APIException(ExceptionEnum.SIGN_ERROR);
        }

        if (runType != 0) {
            Integer vcType = vcApplyReqDto.getCredentialType();
            switch (CrossChainCertificateTypeEnum.valueOf(vcType.byteValue())) {
                case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                    isBackbone(publicKey);
                    break;
                case RELAYER_CERTIFICATE:
                    isSuperNode(publicKey);
                    break;
                case DOMAIN_NAME_CERTIFICATE:
                    isRelayer(publicKey);
                    break;
                default:
                    break;
            }
        }
    }

    public DataResp<VcApplyRespDto> vcApply(VcApplyReqDto vcApplyReqDto) {
        DataResp<VcApplyRespDto> dataResp = new DataResp<>();
        String publicKey = vcApplyReqDto.getPublicKey();
        String signAlgo = vcApplyReqDto.getSignAlgo();
        try {
            //check
            checkVcApply(publicKey, signAlgo, vcApplyReqDto);
            String applyNo = IdGenerator.createApplyNo();
            VcRecordDomain domain = buildVcRecordDomain(applyNo, publicKey, vcApplyReqDto);
            vcRecordService.insert(domain);
            VcApplyRespDto respDto = new VcApplyRespDto();
            respDto.setApplyNo(applyNo);
            dataResp.setData(respDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("vc apply error: {}", e.getMessage());
            dataResp.buildCommonField(ExceptionEnum.SYS_ERROR.getErrorCode(), e.getMessage());
        }
        return dataResp;
    }

    private VcRecordDomain buildVcRecordDomain(String applyNo, String authorizedPublicKey, VcApplyReqDto vcApplyReqDto) {
        VcRecordDomain domain = new VcRecordDomain();
        domain.setApplyNo(applyNo);
        AbstractCrossChainCertificate crossChainCertificate = CrossChainCertificateFactory.createCrossChainCertificate(vcApplyReqDto.getContent());
        PublicKey ownerPublicKey = CrossChainCertificateUtil.getPublicKeyFromCrossChainCertificate(crossChainCertificate);
        domain.setContent(vcApplyReqDto.getContent());
        domain.setCredentialType(vcApplyReqDto.getCredentialType());
        domain.setStatus(StatusEnum.APPLYING.getCode());
        domain.setPublicKey(vcApplyReqDto.getPublicKey());
        domain.setOwnerPublicKey(Base64.encode(ownerPublicKey.getEncoded()));
        ObjectIdentity objectIdentity = new X509PubkeyInfoObjectIdentity(Base64.decode(authorizedPublicKey));
        domain.setUserId(objectIdentity.encode());
        domain.setCreateTime(DateUtil.currentSeconds());
        domain.setIsDownload(0);
        return domain;
    }

    public DataResp<QueryStatusRespDto> applyStatus(QueryStatusReqDto reqDto) {
        DataResp<QueryStatusRespDto> dataResp = new DataResp<>();
        try {
            String applyNo = reqDto.getApplyNo();
            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord(applyNo);
            if (Tools.isNull(vcRecordDomain)) {
                throw new APIException(ExceptionEnum.CREDENTIAL_APPLY_NOT_EXIST);
            }
            Integer status = vcRecordDomain.getStatus();
            QueryStatusRespDto respDto = new QueryStatusRespDto();
            if (StatusEnum.AUDIT_PASS.getCode().equals(status)) {
                respDto.setCredentialId(vcRecordDomain.getVcId());
                respDto.setUserId(ObjectIdentity.decode(vcRecordDomain.getUserId()));
            }
            respDto.setStatus(status);
            dataResp.setData(respDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("query vc apply error: {}", e.getMessage());
            dataResp.buildCommonField(ExceptionEnum.SYS_ERROR.getErrorCode(), e.getMessage());
        }
        return dataResp;
    }

    public DataResp<QueryStatusRespDto> vcStatus(VcInfoReqDto reqDto) {
        DataResp<QueryStatusRespDto> dataResp = new DataResp<>();
        try {
            String credentialId = reqDto.getCredentialId();
            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(credentialId);
            QueryStatusRespDto respDto = new QueryStatusRespDto();
            respDto.setCredentialId(credentialId);
            if (Tools.isNull(vcRecordDomain)) {
                throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
            } else {
                respDto.setUserId(ObjectIdentity.decode(vcRecordDomain.getUserId()));
                respDto.setStatus(vcRecordDomain.getStatus());
            }
            dataResp.setData(respDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("query vc status error: {}", e.getMessage());
            dataResp.buildCommonField(ExceptionEnum.SYS_ERROR.getErrorCode(), e.getMessage());
        }
        return dataResp;
    }

    public DataResp<VcInfoRespDto> vcDownload(VcInfoReqDto reqDto) {
        DataResp<VcInfoRespDto> dataResp = new DataResp<>();
        String vcId = reqDto.getCredentialId();
        String lockKey = Constants.LOCK_CREDENTIAL_DOWNLOAD_PREFIX + vcId;
        try {
            VcInfoRespDto respDto = new VcInfoRespDto();
            //get lock
            boolean acquireLock = distributedLock.acquireLock(lockKey, vcId);
            if (!acquireLock) throw new APIException(ExceptionEnum.SYS_ERROR);

            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(vcId);
            if (Tools.isNull(vcRecordDomain)) {
                throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
            } else if (vcRecordDomain.getIsDownload().equals(1)) {
                throw new APIException(ExceptionEnum.CREDENTIAL_IS_DOWNLOAD);
            }
            vcRecordDomain.setIsDownload(1);
            byte[] vcData = vcRecordDomain.getVcData();
            vcRecordService.updateIsDownloadByVcId(vcRecordDomain);
            respDto.setCredential(vcData);
            dataResp.setData(respDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("download vc error: {}", e.getMessage());
            dataResp.buildSysExceptionField();
        } finally {
            distributedLock.releaseLock(lockKey, vcId);
        }
        return dataResp;
    }

    public DataResp<VcRootRespDto> getVcRoot() {
        DataResp<VcRootRespDto> dataResp = new DataResp<>();
        try {
            VcRootDomain vcRootDomain = vcRootService.getVcRoot();
            VcRootRespDto vcRootRespDto = new VcRootRespDto();
            vcRootRespDto.setBcdnsRootCredential(vcRootDomain.getVcRoot());
            dataResp.setData(vcRootRespDto);
            dataResp.buildSuccessField();
        }  catch (Exception e) {
            logger.error("get root vcerror: {}", e.getMessage());
            dataResp.buildCommonField(ExceptionEnum.SYS_ERROR.getErrorCode(), e.getMessage());
        }
        return dataResp;
    }

    public DataResp<VcPTCTrustRootRespDto> vcAddPTCTrustRoot(VcPTCTrustRootReqDto reqDto) {
        DataResp<VcPTCTrustRootRespDto> dataResp = null;
        VcPTCTrustRootRespDto vcAddPTCTrustRootResp = null;
        try {
            // get owner's privateKey && issuerId
            ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyDomain(1);
            String issuerPrivateKey = ConfigTools.decrypt(decryptPublicKey, apiKeyDomain.getIssuerPrivateKey());
            String issuerId = new PrivateKeyManager(issuerPrivateKey).getEncAddress();

            dataResp = new DataResp<>();
            vcAddPTCTrustRootResp = new VcPTCTrustRootRespDto();
            BIFContractInvokeResponse response = null;
            // read from arguments, decode VcPTCTrustRoot
            byte[] content = reqDto.getPtcTrustRoot();
            PTCTrustRoot ptcTrustRootReq = PTCTrustRoot.decode(content);
            // get certificate from contract
            String vcId = ptcTrustRootReq.getPtcCrossChainCert().getId();
            BIFSDK bifsdk = BIFSDK.getInstance(sdkUrl); // create a chain client
            // call PTCManager contract to get Blockchain DomainName Service issued certificate
            BIFContractCallRequest bifContractCallRequest = new BIFContractCallRequest();
            bifContractCallRequest.setInput(
                    StrUtil.format(
                            GET_CERT_BY_ID, vcId
                    )
            );
            bifContractCallRequest.setContractAddress(ptcContractAddress);
            bifContractCallRequest.setGasPrice(1L);
            BIFContractService bifContractService = bifsdk.getBIFContractService();
            BIFContractCallResponse callResp = bifContractService.contractQuery(bifContractCallRequest);
            // decode byte to ptc certificate
            if (ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())) {
                if (((HashMap<String, Object>) callResp.getResult().getQueryRets().get(0)).containsKey("result")) {
                    // JSONObject result = JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result");
                    // String data = result.getString("data"); // get (bytes)certificate from bif's contract
                    // decode result from contract to get (byte[])certificate
                    String resp = decodeResultFromResponse(callResp);
                    if (Objects.equals(resp, "")) {
                        logger.error("PTC Certificate has not been registered");
                        throw new APIException(
                                ExceptionEnum.CONTRACT_QUERY_ERROR, "PTC Certificate has not been registered"
                        );
                    }
                    AbstractCrossChainCertificate certFromCont = CrossChainCertificateFactory.createCrossChainCertificate(HexUtil.decodeHex(resp)); // decodeResultFromResponse(callResp) maybe has remove '0x'
                    PublicKey publicKey = CrossChainCertificateUtil.getPublicKeyFromCrossChainCertificate(certFromCont); // get cert from bif's contract
                    // verify signature
                    if (ptcTrustRootReq.getSigAlgo().getSigner().verify(
                            publicKey,
                            ptcTrustRootReq.getEncodedToSign(), //data
                            ptcTrustRootReq.getSig()
                    )) {
                        String ptcOidHash = HexUtil.encodeHexStr(HashAlgoEnum.KECCAK_256.hash(
                                ptcTrustRootReq.getPtcCredentialSubject().getApplicant().encode()
                        ));
                        logger.info("upload ptc trust root with oid {}", ptcOidHash);

                        // if ptcTrustRoot has been registered
                        bifContractCallRequest.setInput(
                                StrUtil.format(
                                        // PTCTrustRoot中PTC证书Owner的OID(bytes32)
                                        GET_PTCTRUSTROOT_BY_ID,
                                        "0x" + ptcOidHash
                                )
                        );
                        bifContractCallRequest.setContractAddress(ptcTrustRootContractAddress);
                        callResp = bifContractService.contractQuery(bifContractCallRequest);
                        if (0 != callResp.getErrorCode()) {
                            logger.error(StrUtil.format(
                                    "failed to query PTCTTrustRoot by ptcOid to BIF chain ( err_code: {}, err_msg: {} )",
                                    callResp.getErrorCode(), callResp.getErrorDesc()
                            ));
                            throw new APIException(
                                    ExceptionEnum.CONTRACT_QUERY_ERROR,
                                    StrUtil.format(
                                            "failed to query PTCTTrustRoot by ptcOid to BIF chain ( err_code: {}, err_msg: {} )",
                                            callResp.getErrorCode(), callResp.getErrorDesc()
                                    )
                            );
                        }
                        // upload ptcTrustRoot to PTCTrustRootManager contract
                        BIFContractInvokeRequest bifContractInvokeRequest = new BIFContractInvokeRequest();
                        bifContractInvokeRequest.setSenderAddress(issuerId);
                        bifContractInvokeRequest.setPrivateKey(issuerPrivateKey);
                        bifContractInvokeRequest.setBIFAmount(0L);
                        bifContractInvokeRequest.setGasPrice(1L);
                        bifContractInvokeRequest.setRemarks("contract invoke");
                        bifContractInvokeRequest.setFeeLimit(20000000L);

                        // had not registered: addPTCTrustRoot
                        bifContractInvokeRequest.setInput(
                                StrUtil.format(
                                        ADD_PTCTRUSTROOT_BY_PTCOID_TEMPLATE,
                                        "0x" + ptcOidHash, "0x" + HexUtil.encodeHexStr(content)
                                )
                        );
                        if (((HashMap<String, Object>) callResp.getResult().getQueryRets().get(0)).containsKey("result")) {
                            resp = decodeResultFromResponse(callResp);
                            // has been registered: upgradePTCTR
                            if (!Objects.equals(resp, "")) {
                                bifContractInvokeRequest.setInput(
                                        StrUtil.format(
                                                UPGRADE_PTCTRUSTROOT_BY_PTCOID_TEMPLATE,
                                                "0x" + ptcOidHash, "0x" + HexUtil.encodeHexStr(content)
                                        )
                                );
                            }
                        }
                        bifContractInvokeRequest.setContractAddress(ptcTrustRootContractAddress);
                        response = bifContractService.contractInvoke(bifContractInvokeRequest);
                        if (0 != response.getErrorCode()) {
                            logger.error(StrUtil.format(
                                    "failed to register PTCTTrustRoot to BIF chain ( err_code: {}, err_msg: {} )",
                                    response.getErrorCode(), response.getErrorDesc()
                            ));
                            throw new APIException(
                                    ExceptionEnum.REGISTER_PTCTRUSTROOT_ERROR,
                                    StrUtil.format(
                                            "failed to register PTCTTrustRoot to BIF chain ( err_code: {}, err_msg: {} )",
                                            response.getErrorCode(), response.getErrorDesc()
                                    )
                            );
                        }
                        vcAddPTCTrustRootResp.setStatus(true);
                        vcAddPTCTrustRootResp.setMessage(response.getResult().getHash());
                        dataResp.setData(vcAddPTCTrustRootResp);
                        dataResp.buildSuccessField();
                    } else {
                        logger.error("PTC Certificate verify PTCTrustRoot failed");
                        throw new APIException(
                                ExceptionEnum.PTCTRUSTROOT_SIGN_VERIFY_ERROR, "PTC Certificate verify PTCTrustRoot failed"
                        );
                    }
                }
            } else {
                logger.error(StrUtil.format("failed to query PTC Certificate by ptcOid to BIF chain ( err_code: {}, err_msg: {} )",
                        callResp.getErrorCode(), callResp.getErrorDesc()));
                throw new APIException(
                        ExceptionEnum.CONTRACT_QUERY_ERROR,
                        StrUtil.format(
                                "failed to query PTC Certificate by ptcOid to BIF chain ( err_code: {}, err_msg: {} )",
                                callResp.getErrorCode(), callResp.getErrorDesc()
                        ));
            }
        } catch (APIException e) {
            dataResp.setErrorCode(e.getErrorCode());
            dataResp.setMessage(e.getErrorMessage());
            vcAddPTCTrustRootResp.setStatus(false);
            vcAddPTCTrustRootResp.setMessage("vcAddPTCTrustRoot failed");
            dataResp.setData(vcAddPTCTrustRootResp);
            dataResp.buildAPIExceptionField(e);
            return dataResp;
        } catch (Exception e) {
            dataResp.setErrorCode(ExceptionEnum.SYS_ERROR.getErrorCode());
            dataResp.setMessage(ExceptionEnum.SYS_ERROR.getMessage());
            vcAddPTCTrustRootResp.setStatus(false);
            vcAddPTCTrustRootResp.setMessage("vcAddPTCTrustRoot failed");
            dataResp.setData(vcAddPTCTrustRootResp);
            dataResp.buildAPIExceptionField(new APIException(e));
            return dataResp;
        }
        return dataResp;
    }

    public DataResp<VcTpBtaRespDto> vcAddThirdPartyBlockchainTrustAnchor(VcTpBtaReqDto reqDto) {
        DataResp<VcTpBtaRespDto> dataResp = new DataResp<>();
        VcTpBtaRespDto vcAddTpBtaResp = new VcTpBtaRespDto();
        byte[] tpbta = reqDto.getTpbta();
        try {
            // get owner's privateKey && issuerId
            ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyDomain(1);
            String issuerPrivateKey = ConfigTools.decrypt(decryptPublicKey, apiKeyDomain.getIssuerPrivateKey());
            String issuerId = new PrivateKeyManager(issuerPrivateKey).getEncAddress();

            /*// recover Relayer's cert from BIF PTCManagerContract by relayer cert's vcId in request body
            PublicKey publicKey = new X509PubkeyInfoObjectIdentity(Base64.decode(reqDto.getPublicKey())).getPublicKey();
            String publicKeyStr = Base64.encode(publicKey.getEncoded());
            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4OwnerPubKey(publicKeyStr);
            AbstractCrossChainCertificate certRecover = CrossChainCertificateFactory.createCrossChainCertificate(vcRecordDomain.getContent());*/
            String vcId = reqDto.getVcId(); // RELAYER's vcId
            BIFSDK bifsdk = BIFSDK.getInstance(sdkUrl);
            BIFContractCallRequest bifContractCallRequest = new BIFContractCallRequest();
            bifContractCallRequest.setInput(
                    StrUtil.format(
                            GET_CERT_BY_ID, vcId
                    )
            );
            bifContractCallRequest.setContractAddress(relayContractAddress);
            bifContractCallRequest.setGasPrice(1L);
            BIFContractService bifContractService = bifsdk.getBIFContractService();
            BIFContractCallResponse callResp = bifContractService.contractQuery(bifContractCallRequest);
            if (ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())) {
                if (((HashMap<String, Object>) callResp.getResult().getQueryRets().get(0)).containsKey("result")) {
                    // JSONObject result = JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result");
                    // String data = result.getString("data"); // get (bytes)certificate from bif's contract
                    // decode result from contract to get (byte[])certificate
                    String resp = decodeResultFromResponse(callResp);
                    if (Objects.equals(resp, "")) {
                        logger.error("Relayer Cert has not been registered");
                        throw new APIException(
                                ExceptionEnum.CONTRACT_QUERY_ERROR, "Relayer Cert has not been registered"
                        );
                    }
                    AbstractCrossChainCertificate certRecover = CrossChainCertificateFactory.createCrossChainCertificate(HexUtil.decodeHex(resp)); // decodeResultFromResponse(callResp) maybe has remove '0x'
                    // PublicKey publicKey = CrossChainCertificateUtil.getPublicKeyFromCrossChainCertificate(certRecover);
                    /* 1. verify if the sender's identity is relayer */
                    if (CrossChainCertificateTypeEnum.getTypeByCredentialSubject(certRecover.getCredentialSubjectInstance())
                            != CrossChainCertificateTypeEnum.RELAYER_CERTIFICATE) {
                        throw new APIException(ExceptionEnum.TPBTA_BELONG_TYPE_ERROR, "query cert type error");
                    }
                    // 2. verify if the signature is valid with publicKey which stored in BCDNS service
                    if (!SignAlgoEnum.getByName(reqDto.getSignAlgo()).getSigner().verify(
                            CrossChainCertificateUtil.getPublicKeyFromCrossChainCertificate(certRecover),
                            reqDto.getTpbta(),
                            reqDto.getSign()
                    )) {
                        logger.error("TPBTA's signature verified error");
                        throw new APIException(ExceptionEnum.TPBTA_SIGN_VERIFY_ERROR);
                    }
                    // 3. upload to bif chain's ThirdPartyBlockchainTrustAnchor contract
                    bifContractCallRequest.setContractAddress(tpbtaContractAddress);
                    ThirdPartyBlockchainTrustAnchor tpbtaReq = ThirdPartyBlockchainTrustAnchor.decode(tpbta);
                    ThirdPartyBlockchainTrustAnchor.TypeEnum tpbtaType = ThirdPartyBlockchainTrustAnchor.TypeEnum.parseFrom(tpbtaReq.getCrossChainLane());
                    if (!tpbtaType.equals(ThirdPartyBlockchainTrustAnchor.TypeEnum.BLOCKCHAIN_LEVEL)) {
                        String senderDomain = tpbtaReq.getCrossChainLane().getSenderDomain().getDomain();
                        // check if Blockchain Level TPBTA exist
                        bifContractCallRequest.setInput(
                                StrUtil.format(
                                        GET_TPBTA_BY_LANE, senderDomain, getTPBTALatestVersion(senderDomain)
                                )
                        );
                        callResp = bifContractService.contractQuery(bifContractCallRequest);
                        if (ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())) {
                            if (((HashMap<String, Object>) callResp.getResult().getQueryRets().get(0)).containsKey("result")) {
                                resp = decodeResultFromResponse(callResp);
                                // Blockchain Level TPBTA has been registered
                                if (!Objects.equals(resp, "")) {
                                    logger.error("Blockchain Level TPBTA has not been registered");
                                    throw new APIException(
                                            ExceptionEnum.TPBTA_LEVEL_ERROR, "Blockchain Level TPBTA has not been registered"
                                    );
                                } else {
                                    // 未注册BLOCKCHAIN_LEVEL的TPBTA
                                    if (!tpbtaType.equals(ThirdPartyBlockchainTrustAnchor.TypeEnum.CHANNEL_LEVEL)) {
                                        bifContractCallRequest.setInput(
                                                StrUtil.format(
                                                        GET_TPBTA_BY_LANE,
                                                        StrUtil.builder().append(tpbtaReq.getCrossChainLane().getCrossChainChannel().getSenderDomain().getDomain()).append("@").append(tpbtaReq.getCrossChainLane().getCrossChainChannel().getReceiverDomain().getDomain()).toString(),
                                                        getTPBTALatestVersion(StrUtil.builder().append(tpbtaReq.getCrossChainLane().getCrossChainChannel().getSenderDomain().getDomain()).append("@").append(tpbtaReq.getCrossChainLane().getCrossChainChannel().getReceiverDomain().getDomain()).toString())
                                                )
                                        );
                                        callResp = bifContractService.contractQuery(bifContractCallRequest);
                                        if (ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())) {
                                            if (((HashMap<String, Object>) callResp.getResult().getQueryRets().get(0)).containsKey("result")) {
                                                resp = decodeResultFromResponse(callResp);
                                                if (!Objects.equals(resp, "")) {
                                                    logger.error("Channel Level TPBTA has not been registered");
                                                    throw new APIException(
                                                            ExceptionEnum.TPBTA_LEVEL_ERROR, "Channel Level TPBTA has not been registered"
                                                    );
                                                }
                                            }
                                        } else {
                                            logger.error(StrUtil.format("failed to query TPBTA by lane: {} to BIF chain ( err_code: {}, err_msg: {} )",
                                                    StrUtil.builder().append(tpbtaReq.getCrossChainLane().getCrossChainChannel().getSenderDomain().getDomain()).append("@").append(tpbtaReq.getCrossChainLane().getCrossChainChannel().getReceiverDomain().getDomain()).toString(),
                                                    callResp.getErrorCode(), callResp.getErrorDesc()));
                                            throw new APIException(
                                                    ExceptionEnum.CONTRACT_QUERY_ERROR,
                                                    StrUtil.format(
                                                            StrUtil.format("failed to query TPBTA by lane: {} to BIF chain ( err_code: {}, err_msg: {} )",
                                                                    StrUtil.builder().append(tpbtaReq.getCrossChainLane().getCrossChainChannel().getSenderDomain().getDomain()).append("@").append(tpbtaReq.getCrossChainLane().getCrossChainChannel().getReceiverDomain().getDomain()).toString(),
                                                                    callResp.getErrorCode(), callResp.getErrorDesc())
                                                    )
                                            );
                                        }
                                    }
                                }
                            }
                        } else {
                            logger.error(StrUtil.format("failed to query TPBTA by lane: {} to BIF chain ( err_code: {}, err_msg: {} )",
                                    senderDomain, callResp.getErrorCode(), callResp.getErrorDesc()));
                            throw new APIException(
                                    ExceptionEnum.CONTRACT_QUERY_ERROR,
                                    StrUtil.format(
                                            StrUtil.format("failed to query TPBTA by lane: {} to BIF chain ( err_code: {}, err_msg: {} )",
                                                    senderDomain, callResp.getErrorCode(), callResp.getErrorDesc())
                                    )
                            );
                        }
                    }
                    BIFContractInvokeRequest bifContractInvokeRequest = new BIFContractInvokeRequest();
                    bifContractInvokeRequest.setSenderAddress(issuerId);
                    bifContractInvokeRequest.setPrivateKey(issuerPrivateKey);
                    bifContractInvokeRequest.setContractAddress(tpbtaContractAddress);
                    vcAddTpBtaResp = bifAddThirdPartyBlockchainTrustAnchor(bifContractService, bifContractInvokeRequest, tpbtaReq.getCrossChainLane().getLaneKey(), tpbtaReq.getTpbtaVersion(), tpbta);
                    dataResp.setData(vcAddTpBtaResp);
                    dataResp.buildSuccessField();
                }
            } else {
                logger.error(StrUtil.format("failed to query Relayer Certificate by vcId to BIF chain ( err_code: {}, err_msg: {} )",
                        callResp.getErrorCode(), callResp.getErrorDesc()));
                throw new APIException(
                        ExceptionEnum.CONTRACT_QUERY_ERROR,
                        StrUtil.format(
                                "failed to query Relayer Certificate by vcId to BIF chain ( err_code: {}, err_msg: {} )",
                                callResp.getErrorCode(), callResp.getErrorDesc()
                        ));
            }
        } catch (APIException e) {
            dataResp.setErrorCode(e.getErrorCode());
            dataResp.setMessage(e.getErrorMessage());
            vcAddTpBtaResp.setStatus(false);
            vcAddTpBtaResp.setMessage("vcAddTPBTA failed");
            dataResp.setData(vcAddTpBtaResp);
            dataResp.buildAPIExceptionField(e);
            return dataResp;
        } catch (Exception e) {
            dataResp.setErrorCode(ExceptionEnum.SYS_ERROR.getErrorCode());
            dataResp.setMessage(ExceptionEnum.SYS_ERROR.getMessage());
            vcAddTpBtaResp.setStatus(false);
            vcAddTpBtaResp.setMessage("vcAddPTCTrustRoot failed");
            dataResp.setData(vcAddTpBtaResp);
            dataResp.buildAPIExceptionField(new APIException(e));
            return dataResp;
        }
        return dataResp;
    }

    private String decodeResultFromResponse(BIFContractCallResponse response) {
        Map<String, Map<String, String>> resMap = (Map<String, Map<String, String>>) (response.getResult().getQueryRets().get(0));
        String res = resMap.get("result").get("data").trim();
        res = StrUtil.removeSuffix(
                StrUtil.removePrefix(res, "[").trim(),
                "]"
        ).trim();
        if (HexUtil.isHexNumber(res)) {
            res = StrUtil.removePrefix(res.trim(), "0x");
        }
        return res;
    }

    private VcTpBtaRespDto bifAddThirdPartyBlockchainTrustAnchor(
            BIFContractService bifContractService,
            BIFContractInvokeRequest bifContractInvokeRequest,
            String tpbtaLane,
            int tpbtaVersion,
            byte[] tpbta
    ) {
        bifContractInvokeRequest.setInput(
                StrUtil.format(
                        ADD_TPBTA_BY_LANE, tpbtaLane, tpbtaVersion, "0x" + HexUtil.encodeHexStr(tpbta) // yuechi: maybe wrong???
                )
        );
        bifContractInvokeRequest.setBIFAmount(0L);
        bifContractInvokeRequest.setGasPrice(1L);
        BIFContractInvokeResponse response = bifContractService.contractInvoke(bifContractInvokeRequest);
        if (0 != response.getErrorCode()) {
            throw new APIException(
                    ExceptionEnum.REGISTER_TPBTA_ERROR,
                    StrUtil.format(
                            "failed to register TPBTA to BIF chain ( err_code: {}, err_msg: {} )",
                            response.getErrorCode(), response.getErrorDesc()
                    )
            );
        }
        VcTpBtaRespDto vcTpBtaRespDto = new VcTpBtaRespDto();
        vcTpBtaRespDto.setStatus(true);
        vcTpBtaRespDto.setMessage(response.getResult().getHash());
        return vcTpBtaRespDto;
    }

    public String getTPBTALatestVersion(String tpbtaLane) {
        String result = "";
        BIFSDK bifsdk = BIFSDK.getInstance(sdkUrl);
        BIFContractService bifContractService = bifsdk.getBIFContractService();
        BIFContractCallRequest bifContractCallRequest = new BIFContractCallRequest();
        bifContractCallRequest.setContractAddress(tpbtaContractAddress);
        bifContractCallRequest.setInput(
                StrUtil.format(
                        GET_TPBTA_LATEST_VERSION_BY_LANE,
                        tpbtaLane
                )
        );
        BIFContractCallResponse callResp = bifContractService.contractQuery(bifContractCallRequest);
        if (ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())) {
            if (((HashMap<String, Object>) callResp.getResult().getQueryRets().get(0)).containsKey("result")) {
                result = decodeResultFromResponse(callResp);
            }
        } else {
            throw new APIException(ExceptionEnum.PARAME_ERROR);
        }
        return result;
    }
}
