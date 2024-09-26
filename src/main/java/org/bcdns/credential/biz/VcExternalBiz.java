package org.bcdns.credential.biz;


import cn.bif.api.BIFSDK;
import cn.bif.common.JsonUtils;
import cn.bif.model.request.BIFContractCallRequest;
import cn.bif.model.request.BIFContractInvokeRequest;
import cn.bif.model.response.BIFContractCallResponse;
import cn.bif.model.response.BIFContractInvokeResponse;
import cn.bif.module.contract.BIFContractService;
import cn.bif.module.encryption.key.PublicKeyManager;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSONObject;
import com.alipay.antchain.bridge.commons.bcdns.*;
import com.alipay.antchain.bridge.commons.bcdns.utils.CrossChainCertificateUtil;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentityType;
import com.alipay.antchain.bridge.commons.core.ptc.PTCTrustRoot;
import com.alipay.antchain.bridge.commons.core.ptc.ThirdPartyBlockchainTrustAnchor;
import com.alipay.antchain.bridge.commons.core.ptc.ThirdPartyBlockchainTrustAnchorV1;
import com.alipay.antchain.bridge.commons.exception.AntChainBridgeCommonsException;
import com.alipay.antchain.bridge.commons.exception.CommonsErrorCodeEnum;
import org.bcdns.credential.common.constant.Constants;
import org.bcdns.credential.common.utils.IdGenerator;
import org.bcdns.credential.common.utils.Tools;
import org.bcdns.credential.dto.req.*;
import org.bcdns.credential.dto.resp.*;
import org.bcdns.credential.enums.ExceptionEnum;
import org.bcdns.credential.enums.StatusEnum;
import org.bcdns.credential.exception.APIException;
import org.bcdns.credential.model.VcAuditDomain;
import org.bcdns.credential.model.VcRecordDomain;
import org.bcdns.credential.model.VcRootDomain;
import org.bcdns.credential.service.VcAuditService;
import org.bcdns.credential.service.VcRecordService;
import org.bcdns.credential.service.VcRootService;
import org.bcdns.credential.utils.DistributedLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;


@Component
public class VcExternalBiz {

    @Value("${dpos.contract.address}")
    private String dposContractAddress;

    @Value("${ptc.contract.address}")
    private String ptcContractAddress;

    @Value("${relay.contract.address}")
    private String relayContractAddress;

    @Value("${ptc-trust-root.contract.address}")
    private String ptcTrustRootContractAddress;

    @Value("${tpbta.contract.address}}")
    private String tpbtaContractAddress;

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

    @Value("${sdk.url}")
    private String sdkUrl;

    @Value("${owner.address}}")
    private String ownerAddress;

    @Value("$owner.privateKey")
    private String ownerPrivateKey;

    private static final String GET_CERT_BY_ID
            = "{\"function\":\"getCertById(string)\",\"args\":\"'{}'\"}";

    private static final String GET_PTCTRUSTROOT_BY_ID
            = "{\"function\":\"getPTCTrustRootById(bytes32)\",\"args\":\"'{}'\"}";

    private static final String ADD_PTCTRUSTROOT_BY_PTCOID_TEMPLATE
            = "{\"function\":\"addPTCTR(bytes32,bytes)\",\"args\":\"'{}','{}'\"}";

    private static final String UPGRADE_PTCTRUSTROOT_BY_PTCOID_TEMPLATE
            = "{\"function\":\"upgradePTCTR(bytes32,bytes)\",\"args\":\"'{}','{}'\"}";

    private static final String BINDING_DOMAIN_NAME_WITH_TPBTA_TEMPLATE
            = "{\"function\":\"bindingDomainNameWithTPBTA(string,bytes)\",\"args\":\"'{}','{}'\"}";

    private void isBackbone(String publicKey) {
        PublicKeyManager publicKeyManager = new PublicKeyManager(publicKey);
        BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
        String input = StrUtil.format("{\"method\":\"getnodeinfo\",\"params\":{\"address\":\"{}\"}}", publicKeyManager.getEncAddress());
        BIFContractCallRequest bifContractCallRequest = new BIFContractCallRequest();
        bifContractCallRequest.setInput(input);
        bifContractCallRequest.setContractAddress(dposContractAddress);
        BIFContractService contractService = sdk.getBIFContractService();
        BIFContractCallResponse callResp = contractService.contractQuery(bifContractCallRequest);
        if (ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())) {
            if (JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result") != null) {
                JSONObject result = JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result");
                String roleType = result.getJSONObject("data").getJSONObject("nodeInfo").getString("roleType");
                if (!"backbone".equals(roleType)) {
                    throw new APIException(ExceptionEnum.PARAME_ERROR);
                }
            } else {
                throw new APIException(ExceptionEnum.PARAME_ERROR);
            }
        } else {
            throw new APIException(ExceptionEnum.PARAME_ERROR);
        }
    }

    private void isSuperNode(String publicKey) {
        PublicKeyManager publicKeyManager = new PublicKeyManager(publicKey);
        BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
        String input = StrUtil.format("{\"method\":\"getnodeinfo\",\"params\":{\"address\":\"{}\"}}", publicKeyManager.getEncAddress());
        BIFContractCallRequest bifContractCallRequest = new BIFContractCallRequest();
        bifContractCallRequest.setInput(input);
        bifContractCallRequest.setContractAddress(dposContractAddress);
        BIFContractService contractService = sdk.getBIFContractService();
        BIFContractCallResponse callResp = contractService.contractQuery(bifContractCallRequest);

        if (ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())) {
            if (JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result") != null) {
                JSONObject result = JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result");
                String roleType = result.getJSONObject("data").getJSONObject("nodeInfo").getString("roleType");
                if (!"super".equals(roleType) && !"validator".equals(roleType)) {
                    throw new APIException(ExceptionEnum.PARAME_ERROR);
                }
            } else {
                throw new APIException(ExceptionEnum.PARAME_ERROR);
            }
        } else {
            throw new APIException(ExceptionEnum.PARAME_ERROR);
        }
    }

    private void isRelayer(String publicKey) {
        PublicKeyManager publicKeyManager = new PublicKeyManager(publicKey);
        ObjectIdentity objectIdentity = new ObjectIdentity(ObjectIdentityType.BID, publicKeyManager.getEncAddress().getBytes());
        VcAuditDomain vcAuditDomain = vcAuditService.getVcIdByVcOwner(objectIdentity.encode());
        if (Tools.isNull(vcAuditDomain)) {
            throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
        }

        VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(vcAuditDomain.getVcId());
        if (Tools.isNull(vcRecordDomain)) {
            throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
        }
        if (!vcRecordDomain.getCredentialType().equals(3)) {
            throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
        }
        if (vcRecordDomain.getStatus().equals(StatusEnum.REVOKE.getCode())) {
            throw new APIException(ExceptionEnum.CREDENTIAL_IS_REVOKE);
        }
    }

    private void checkVcApply(String publicKey, VcApplyReqDto vcApplyReqDto) throws Exception {
        //sign verify
        byte[] sign = vcApplyReqDto.getSign();
        byte[] content = vcApplyReqDto.getContent();
        boolean verifyResult;
        verifyResult = PublicKeyManager.verify(content, sign, publicKey);
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
                    throw new AntChainBridgeCommonsException(
                            CommonsErrorCodeEnum.BCDNS_UNSUPPORTED_CA_TYPE,
                            "failed to parse type from subject class " + vcType
                    );
            }
        }
    }

    public DataResp<VcApplyRespDto> vcApply(VcApplyReqDto vcApplyReqDto) {
        DataResp<VcApplyRespDto> dataResp = new DataResp<>();
        String publicKey = vcApplyReqDto.getPublicKey();
        try {
            //check
            checkVcApply(publicKey, vcApplyReqDto);
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
            logger.error("申请凭证接口异常", e);
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }

    private VcRecordDomain buildVcRecordDomain(String applyNo, String publicKey, VcApplyReqDto vcApplyReqDto) {
        VcRecordDomain domain = new VcRecordDomain();
        domain.setApplyNo(applyNo);
        domain.setContent(vcApplyReqDto.getContent());
        domain.setCredentialType(vcApplyReqDto.getCredentialType());
        domain.setStatus(StatusEnum.APPLYING.getCode());
        domain.setPublicKey(vcApplyReqDto.getPublicKey());
        PublicKeyManager publicKeyManager = new PublicKeyManager(publicKey);
        ObjectIdentity objectIdentity = new ObjectIdentity(ObjectIdentityType.BID, publicKeyManager.getEncAddress().getBytes());
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
            logger.error("query vcStatus error:{}", e);
            dataResp.buildSysExceptionField();
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
            logger.error("query vcStatus error:{}", e);
            dataResp.buildSysExceptionField();
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
            logger.error("query vcStatus error:{}", e);
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
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("get root vc", e);
            dataResp.buildSysExceptionField();
        }

        return dataResp;
    }

    public DataResp<VcPTCTrustRootRespDto> vcAddPTCTrustRoot(VcPTCTrustRootReqDto reqDto) {
        DataResp<VcPTCTrustRootRespDto> dataResp = new DataResp<>();
        // read from arguments, decode VcPTCTrustRoot
        byte[] content = reqDto.getContent();
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
        BIFContractService bifContractService = bifsdk.getBIFContractService();
        BIFContractCallResponse callResp = bifContractService.contractQuery(bifContractCallRequest);
        // decode byte to ptc certificate
        try {
            if (ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())) {
                if (JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result") != null) {
                    // JSONObject result = JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result");
                    // String data = result.getString("data"); // get (bytes)certificate from bif's contract
                    // decode result from contract to get (byte[])certificate
                    String resp = decodeResultFromResponse(callResp);
                    AbstractCrossChainCertificate certFromCont = CrossChainCertificateFactory.createCrossChainCertificate(HexUtil.decodeHex(resp)); // decodeResultFromResponse(callResp) maybe has remove '0x'
                    PublicKey publicKey = CrossChainCertificateUtil.getPublicKeyFromCrossChainCertificate(certFromCont); // get cert from bif's contract
                    // verify signature
                    if (ptcTrustRootReq.getSigAlgo().getSigner().verify(
                            publicKey,
                            ptcTrustRootReq.getEncodedToSign(), //data
                            ptcTrustRootReq.getSig()
                    )) {
                        // if ptcTrustRoot has been registered
                        bifContractCallRequest.setContractAddress(ptcTrustRootContractAddress);
                        bifContractCallRequest.setInput(
                                StrUtil.format(
                                        GET_PTCTRUSTROOT_BY_ID, reqDto.getPtcOid()
                                )
                        );
                        // BIF test net has some problems about gas calculation
                        // So we just set gas manually here.
                        // would delete it in the future.
                        bifContractCallRequest.setGasPrice(1L);

                        callResp = bifContractService.contractQuery(bifContractCallRequest);
                        if (0 != callResp.getErrorCode()) {
                            throw new APIException(
                                    ExceptionEnum.REGISTER_PTCTRUSTROOT_ERROR,
                                    StrUtil.format(
                                            "failed to query PTCTTrustRoot by ptcOid to BIF chain ( err_code: {}, err_msg: {} )",
                                            callResp.getErrorCode(), callResp.getErrorDesc()
                                    )
                            );
                        }
                        // upload ptcTrustRoot to PTCTrustRootManager contract
                        BIFContractInvokeRequest bifContractInvokeRequest = new BIFContractInvokeRequest();
                        // String senderAddress = "did:bid:efYqASNNKhotQLdJH9N83jniXJyinmDX";
                        // String senderPrivateKey = "priSPKkeE5bJuRdsbBeYRMHR6vF6M6PJV97jbwAHomVQodn3x3";
                        bifContractInvokeRequest.setSenderAddress(ownerAddress);
                        bifContractInvokeRequest.setPrivateKey(ownerPrivateKey);
                        // not registered: addPTCTR
                        bifContractInvokeRequest.setInput(
                                StrUtil.format(
                                        ADD_PTCTRUSTROOT_BY_PTCOID_TEMPLATE,
                                        reqDto.getPtcOid(), "0x" + HexUtil.encodeHexStr(content)
                                )
                        );
                        if (JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result") != null) {
                            resp = decodeResultFromResponse(callResp);
                            // has been registered: upgradePTCTR
                            if (!Objects.equals(resp, "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000")) {
                                bifContractInvokeRequest.setInput(
                                        StrUtil.format(
                                                UPGRADE_PTCTRUSTROOT_BY_PTCOID_TEMPLATE,
                                                reqDto.getPtcOid(), "0x" + HexUtil.encodeHexStr(content)
                                        )
                                );
                            }
                        }
                        bifContractInvokeRequest.setContractAddress(ptcTrustRootContractAddress);
                        BIFContractInvokeResponse response = bifContractService.contractInvoke(bifContractInvokeRequest);
                        // deal add PTCTrustRoot's response
                        if (0 != response.getErrorCode()) {
                            throw new APIException(
                                    ExceptionEnum.REGISTER_PTCTRUSTROOT_ERROR,
                                    StrUtil.format(
                                            "failed to register PTCTTrustRoot to BIF chain ( err_code: {}, err_msg: {} )",
                                            response.getErrorCode(), response.getErrorDesc()
                                    )
                            );
                        }
                        VcPTCTrustRootRespDto vcPTCTrustRootRespDto = new VcPTCTrustRootRespDto();
                        vcPTCTrustRootRespDto.setStatus(true);
                        vcPTCTrustRootRespDto.setTxHash(response.getResult().getHash());
                        dataResp.setData(vcPTCTrustRootRespDto);
                    } else {
                        logger.error("addPTCTrustRoot verify signature failed");
                        throw new APIException(ExceptionEnum.PTCTRUSTROOT_SIGN_VERIFY_ERROR);
                    }
                }
            }
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        }
        return dataResp;
    }

    public DataResp<VcTpBtaRespDto> vcAddThirdPartyBlockchainTrustAnchor(VcTpBtaReqDto reqDto) {
        DataResp<VcTpBtaRespDto> dataResp = new DataResp<>();
        byte[] content = reqDto.getContent();
        // decode byte to TPBTA
        // ThirdPartyBlockchainTrustAnchor tpbta = new ThirdPartyBlockchainTrustAnchorV1();
        // ThirdPartyBlockchainTrustAnchor tpbta = ThirdPartyBlockchainTrustAnchor.decode(content);
        BIFSDK bifsdk = BIFSDK.getInstance(sdkUrl); // create a chain client
        // read certificate from database by publicKey
        String publicKey = reqDto.getPublicKey();
        PublicKeyManager publicKeyManager = new PublicKeyManager(publicKey);
        ObjectIdentity objectIdentity = new ObjectIdentity(ObjectIdentityType.BID, publicKeyManager.getEncAddress().getBytes());
        VcAuditDomain vcAuditDomain = vcAuditService.getVcIdByVcOwner(objectIdentity.encode());
        if (Tools.isNull(vcAuditDomain)) {
            throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
        }
        VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(vcAuditDomain.getVcId());
        // get certificate
        // Integer credentialType = vcRecordDomain.getCredentialType();
        // if(credentialType == CrossChainCertificateTypeEnum.RELAYER_CERTIFICATE.ordinal()) {}
        AbstractCrossChainCertificate certRecover = CrossChainCertificateFactory.createCrossChainCertificate(vcRecordDomain.getContent());
        // verify if the sender's identity is relayer
        try {
            if (CrossChainCertificateTypeEnum.getTypeByCredentialSubject(certRecover.getCredentialSubjectInstance())
                    != CrossChainCertificateTypeEnum.RELAYER_CERTIFICATE) {
                throw new APIException(ExceptionEnum.TPBTA_TYPE_ERROR);
            }
            ;
            // verify if the sig is valid
            byte[] sign = reqDto.getSign();
            PublicKeyManager pubKeyInBCDNS = new PublicKeyManager(vcRecordDomain.getPublicKey());
            if (!pubKeyInBCDNS.verify(content, reqDto.getSign())) {
                throw new APIException(ExceptionEnum.TPBTA_SIGN_VERIFY_ERROR);
            }
            // upload to bif chain's ThirdPartyBlockchainTrustAnchor contract
            BIFContractInvokeRequest bifContractInvokeRequest = new BIFContractInvokeRequest();
            // String senderAddress = "did:bid:efYqASNNKhotQLdJH9N83jniXJyinmDX";
            // String senderPrivateKey = "priSPKkeE5bJuRdsbBeYRMHR6vF6M6PJV97jbwAHomVQodn3x3";
            // String addTpBtaInput = StrUtil.format("{\"function\":\"addTPBTA(string,bytes)\",\"args\":\"'{}','{}'\"}", publicKey, "0x" + HexUtil.encodeHexStr(content));
            bifContractInvokeRequest.setSenderAddress(ownerAddress);
            bifContractInvokeRequest.setPrivateKey(ownerPrivateKey);
            bifContractInvokeRequest.setContractAddress(relayContractAddress);
            bifContractInvokeRequest.setInput(
                    StrUtil.format(
                            BINDING_DOMAIN_NAME_WITH_TPBTA_TEMPLATE,
                            reqDto.getDomainName(), content
                    )
            );
            BIFContractService bifContractService = bifsdk.getBIFContractService();
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
            vcTpBtaRespDto.setTxHash(response.getResult().getHash());
            dataResp.setData(vcTpBtaRespDto);
        } catch (APIException e) {
            logger.error("vcAddTpBta failed", e);
            dataResp.buildAPIExceptionField(e);
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
}
