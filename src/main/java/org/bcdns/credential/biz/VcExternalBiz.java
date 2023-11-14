package org.bcdns.credential.biz;


import cn.bif.api.BIFSDK;
import cn.bif.model.crypto.KeyPairEntity;
import cn.bif.model.request.BIFContractCallRequest;
import cn.bif.model.response.BIFContractCallResponse;
import cn.bif.module.contract.BIFContractService;
import cn.bif.module.encryption.key.PrivateKeyManager;
import cn.bif.module.encryption.key.PublicKeyManager;
import cn.bif.utils.hex.HexFormat;
import cn.hutool.core.date.DateUtil;
import com.alibaba.fastjson.JSONObject;
import com.alipay.antchain.bridge.commons.bcdns.*;
import com.alipay.antchain.bridge.commons.core.base.CrossChainDomain;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentityType;
import com.alipay.antchain.bridge.commons.core.ptc.PTCTypeEnum;
import com.alipay.antchain.bridge.commons.exception.AntChainBridgeCommonsException;
import com.alipay.antchain.bridge.commons.exception.CommonsErrorCodeEnum;
import org.bcdns.credential.common.constant.Constants;
import org.bcdns.credential.common.utils.IdGenerator;
import org.bcdns.credential.common.utils.Tools;
import org.bcdns.credential.dao.domain.VcAuditDomain;
import org.bcdns.credential.dao.domain.VcRecordDomain;
import org.bcdns.credential.dao.domain.VcRootDomain;
import org.bcdns.credential.dto.req.QueryStatusReqDto;
import org.bcdns.credential.dto.req.VcApplyReqDto;
import org.bcdns.credential.dto.req.VcInfoReqDto;
import org.bcdns.credential.dto.resp.*;
import org.bcdns.credential.enums.ExceptionEnum;
import org.bcdns.credential.enums.StatusEnum;
import org.bcdns.credential.exception.APIException;
import org.bcdns.credential.service.VcAuditService;
import org.bcdns.credential.service.VcRecordService;
import org.bcdns.credential.service.VcRootService;
import org.bcdns.credential.utils.DistributedLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.security.KeyPair;


@Component
public class VcExternalBiz {

    @Value("${object-identity-type}")
    private Integer objectIdentityType;

    @Value("${dpos.contract.address}")
    private String dposContractAddress;

    private static final Logger logger = LoggerFactory.getLogger(VcExternalBiz.class);

    @Resource
    private VcRecordService vcRecordService;
    @Resource
    private VcRootService vcRootService;

    @Resource
    private VcAuditService vcAuditService;

    @Autowired
    private DistributedLock distributedLock;

    @Value("${sdk.url}")
    private String sdkUrl;

    private void isBackbone(String address) {
        BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
        JSONObject params = new JSONObject();
        params.put("address", address);
        JSONObject input = new JSONObject();
        input.put("method", "getnodeinfo");
        input.put("params", params);
        BIFContractService contractService = sdk.getBIFContractService();
        // Call contractQuery
        BIFContractCallRequest bifContractCallRequest = new BIFContractCallRequest();
        bifContractCallRequest.setInput(input.toJSONString());
        //todo config
        bifContractCallRequest.setContractAddress(dposContractAddress);
        BIFContractCallResponse callResp = contractService.contractQuery(bifContractCallRequest);

        if(ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())){
            if(JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result") != null){
                JSONObject result = JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result");
                String roleType = result.getJSONObject("data").getJSONObject("nodeInfo").getString("roleType");
                if(!"backbone".equals(roleType)){
                    throw new APIException(ExceptionEnum.PARAME_ERROR);
                }
            }else {
                throw new APIException(ExceptionEnum.PARAME_ERROR);
            }
        }else {
            throw new APIException(ExceptionEnum.PARAME_ERROR);
        }
    }

    private void isSuperNode(String address) {
        BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
        JSONObject params = new JSONObject();
        params.put("address", address);
        JSONObject input = new JSONObject();
        input.put("method", "getnodeinfo");
        input.put("params", params);
        BIFContractService contractService = sdk.getBIFContractService();
        // Call contractQuery
        BIFContractCallRequest bifContractCallRequest = new BIFContractCallRequest();
        bifContractCallRequest.setInput(input.toJSONString());
        bifContractCallRequest.setContractAddress(dposContractAddress);
        BIFContractCallResponse callResp = contractService.contractQuery(bifContractCallRequest);

        if(ExceptionEnum.SUCCESS.getErrorCode().equals(callResp.getErrorCode())){
            if(JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result") != null){
                JSONObject result = JSONObject.parseObject(JSONObject.toJSONString(callResp.getResult().getQueryRets().get(0))).getJSONObject("result");
                String roleType = result.getJSONObject("data").getJSONObject("nodeInfo").getString("roleType");
                if(!"super".equals(roleType) && !"validator".equals(roleType)){
                    throw new APIException(ExceptionEnum.PARAME_ERROR);
                }
            }else {
                throw new APIException(ExceptionEnum.PARAME_ERROR);
            }
        }else {
            throw new APIException(ExceptionEnum.PARAME_ERROR);
        }
    }

    private void isRelayer(String address) {
        //todo
        ObjectIdentity objectIdentity = new ObjectIdentity(ObjectIdentityType.BID, address.getBytes());
        VcAuditDomain vcAuditDomain = vcAuditService.getVcIdByVcOwner(objectIdentity.encode());
        VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(vcAuditDomain.getVcId());
        if(Tools.isNull(vcRecordDomain)){
            throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
        }
        if (!vcRecordDomain.getCredentialType().equals(3)) {
            throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
        }
        if (vcRecordDomain.getStatus().equals(StatusEnum.REVOKE.getCode())) {
            throw new APIException(ExceptionEnum.CREDENTIAL_IS_REVOKE);
        }
    }

    private void checkVcApply(String publicKey, String address, VcApplyReqDto vcApplyReqDto){
        //sign verify
        byte[] sign = vcApplyReqDto.getSign();
        byte[] content = vcApplyReqDto.getContent();
        boolean verifyResult = PublicKeyManager.verify(content, sign, publicKey);
        //boolean verifyResult = PublicKeyManager.verify(content, HexFormat.hexStringToBytes(sign), publicKey);
        if(!verifyResult){
            throw new APIException(ExceptionEnum.SIGN_ERROR);
        }

        Integer credentailType = vcApplyReqDto.getCredentialType();
        switch (CrossChainCertificateTypeEnum.valueOf(credentailType.byteValue())){
            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                isBackbone(address);
                break;
            case RELAYER_CERTIFICATE:
                isSuperNode(address);
                break;
            case DOMAIN_NAME_CERTIFICATE:
                isRelayer(address);
                break;
            default:
                throw new AntChainBridgeCommonsException(
                        CommonsErrorCodeEnum.BCDNS_UNSUPPORTED_CA_TYPE,
                        "failed to parse type from subject class " + credentailType
                );
        }
    }

    public DataResp<VcApplyRespDto> vcApply(VcApplyReqDto vcApplyReqDto) {
        //test ptc
//        PrivateKeyManager privateKeyManager = new PrivateKeyManager("priSPKtsBa7FZVFH98WTBUiCS2zJ1fRyExFRpU1aQuLt4QYZws");
//        KeyPairEntity keyPair = KeyPairEntity.getBidAndKeyPair();
//        PTCContentEntity ptcContentEntity = new PTCContentEntity(
//                "test",
//                PTCTypeEnum.BLOCKCHAIN,
//                new ObjectIdentity(ObjectIdentityType.BID, keyPair.getEncAddress().getBytes()),
//                keyPair.getEncPublicKey()
//        );
//        vcApplyReqDto.setContent(ptcContentEntity.encode());
//        vcApplyReqDto.setCredentialType(2);
//        vcApplyReqDto.setPublicKey(privateKeyManager.getEncPublicKey());
//        vcApplyReqDto.setSign(privateKeyManager.sign(ptcContentEntity.encode()));

        //test relay
//        PrivateKeyManager privateKeyManager = new PrivateKeyManager("priSPKUudyVAi5WrhHJU1vCJZYyBL5DNd36MPhbYgHuDPz5E7r");
//        KeyPairEntity keyPair = KeyPairEntity.getBidAndKeyPair();
//        RelayContentEntity relayContentEntity = new RelayContentEntity(
//                "test",
//                new ObjectIdentity(ObjectIdentityType.BID, keyPair.getEncAddress().getBytes()),
//                keyPair.getEncPublicKey()
//        );
//        logger.info("relayer private key: " + keyPair.getEncPrivateKey());
//        logger.info("relayer public key: " + keyPair.getEncPublicKey());
//        logger.info("relayer address: " + keyPair.getEncAddress());
//        vcApplyReqDto.setContent(relayContentEntity.encode());
//        vcApplyReqDto.setCredentialType(3);
//        vcApplyReqDto.setPublicKey(privateKeyManager.getEncPublicKey());
//        vcApplyReqDto.setSign(privateKeyManager.sign(relayContentEntity.encode()));

        //test domain name
        PrivateKeyManager privateKeyManager = new PrivateKeyManager("priSPKqG42jQ32itq6BtUZya9nzBPifUJ7KaUemQ7WR9cQSMGy");
        KeyPairEntity keyPair = KeyPairEntity.getBidAndKeyPair();
        DomainNameContentEntity domainNameContentEntity = new DomainNameContentEntity(
                DomainNameTypeEnum.DOMAIN_NAME,
                new CrossChainDomain("xinghuo"),
                new ObjectIdentity(ObjectIdentityType.BID, keyPair.getEncAddress().getBytes()),
                keyPair.getEncPublicKey()
        );
        vcApplyReqDto.setContent(domainNameContentEntity.encode());
        vcApplyReqDto.setCredentialType(1);
        vcApplyReqDto.setPublicKey(privateKeyManager.getEncPublicKey());
        vcApplyReqDto.setSign(privateKeyManager.sign(domainNameContentEntity.encode()));

        DataResp<VcApplyRespDto> dataResp = new DataResp<VcApplyRespDto>();
        String publicKey = vcApplyReqDto.getPublicKey();
        PublicKeyManager publicKeyManager = new PublicKeyManager(publicKey);
        String applicant =  publicKeyManager.getEncAddress();

        try {
            //check
            //todo test
            checkVcApply(publicKey, applicant, vcApplyReqDto);
            String applyNo = IdGenerator.createApplyNo();
            VcRecordDomain domain = buildVcRecordDomain(applyNo, applicant, vcApplyReqDto);
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

    private VcRecordDomain buildVcRecordDomain(String applyNo, String applicant, VcApplyReqDto vcApplyReqDto){
        VcRecordDomain domain = new VcRecordDomain();
        domain.setApplyNo(applyNo);
        domain.setContent(vcApplyReqDto.getContent());
        domain.setCredentialType(vcApplyReqDto.getCredentialType());
        domain.setStatus(StatusEnum.APPLYING.getCode());
        domain.setPublicKey(vcApplyReqDto.getPublicKey());
        ObjectIdentity objectIdentity = new ObjectIdentity(ObjectIdentityType.parseFromValue(objectIdentityType), applicant.getBytes());
        domain.setCreateTime(DateUtil.currentSeconds());
        domain.setUserId(objectIdentity.encode());
        domain.setIsDownload(0);
        return domain;
    }

    public DataResp<QueryStatusRespDto> applyStatus(QueryStatusReqDto reqDto) {
        DataResp<QueryStatusRespDto> dataResp = new DataResp<>();
        try {
            String applyNo = reqDto.getApplyNo();
            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord(applyNo);
            if(Tools.isNull(vcRecordDomain)){
                throw new APIException(ExceptionEnum.CREDENTIAL_APPLY_NOT_EXIST);
            }
            Integer status = vcRecordDomain.getStatus();
            QueryStatusRespDto respDto = new QueryStatusRespDto();
            if(StatusEnum.AUDIT_PASS.getCode().equals(status)){
                respDto.setCredentialId(vcRecordDomain.getVcId());
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
        DataResp<QueryStatusRespDto> dataResp = new DataResp<QueryStatusRespDto>();
        try {
            String credentialId = reqDto.getCredentialId();
            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(credentialId);
            QueryStatusRespDto respDto = new QueryStatusRespDto();
            respDto.setCredentialId(credentialId);
            if(Tools.isNull(vcRecordDomain)){
                throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
            } else {
                ObjectIdentity objectIdentity = new ObjectIdentity(ObjectIdentityType.BID, vcRecordDomain.getUserId());
                respDto.setUserId(objectIdentity);
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
        DataResp<VcInfoRespDto> dataResp = new DataResp<VcInfoRespDto>();
        String vcId = reqDto.getCredentialId();
        String lockKey = Constants.LOCK_CREDENTIAL_DOWNLOAD_PREFIX + vcId;
        try {
            VcInfoRespDto respDto = new VcInfoRespDto();
            //get lock
            boolean acquireLock = distributedLock.acquireLock(lockKey, vcId);
            if(!acquireLock) throw new APIException(ExceptionEnum.SYS_ERROR);

            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(vcId);
            if(Tools.isNull(vcRecordDomain)){
                throw new APIException(ExceptionEnum.CREDENTIAL_ID_NOT_EXIST);
            }else if(vcRecordDomain.getIsDownload().equals(true)){
                throw new APIException(ExceptionEnum.CREDENTIAL_IS_DOWNLOAD);
            }
            byte[] vcData = vcRecordDomain.getVcData();
            vcRecordService.updateIsDownloadByVcId(1, vcId);
            respDto.setCredential(vcData);
            dataResp.setData(respDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("query vcStatus error:{}", e);
            dataResp.buildSysExceptionField();
        }finally {
            distributedLock.releaseLock(lockKey, vcId);
        }
        return dataResp;
    }

    public DataResp<VcRootRespDto> getVcRoot() {
        DataResp<VcRootRespDto> dataResp = new DataResp<VcRootRespDto>();
        try {
            VcRootDomain vcRootDomain = vcRootService.getVcRoot();
            VcRootRespDto vcRootRespDto = new VcRootRespDto();
            vcRootRespDto.setBcdnsRootCredential(vcRootDomain.getVcRoot());
            dataResp.setData(vcRootRespDto);
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
