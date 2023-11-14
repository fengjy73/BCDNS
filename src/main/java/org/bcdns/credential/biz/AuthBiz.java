package org.bcdns.credential.biz;

import cn.bif.utils.hex.HexFormat;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentityType;
import org.bcdns.credential.common.constant.Constants;
import org.bcdns.credential.common.utils.JwtUtil;
import org.bcdns.credential.common.utils.RedisUtil;
import org.bcdns.credential.common.utils.Tools;
import org.bcdns.credential.dao.domain.ApiKeyDomain;
import org.bcdns.credential.dto.req.AccessTokenReqDto;
import org.bcdns.credential.dto.resp.AccessTokenRespDto;
import org.bcdns.credential.dto.resp.DataResp;
import org.bcdns.credential.enums.ExceptionEnum;
import org.bcdns.credential.exception.APIException;
import org.bcdns.credential.service.ApiKeyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;
@Component
public class AuthBiz {

    private static final Logger logger = LoggerFactory.getLogger(AuthBiz.class);
    @Resource
    private ApiKeyService apiKeyService;

    @Resource
    private RedisUtil redisUtil;

    @Value("${object-identity-type}")
    private Integer objectIdentityType;

    public DataResp<AccessTokenRespDto> getAccessToken(AccessTokenReqDto accessTokenReqDto){
        DataResp<AccessTokenRespDto> dataResp = new DataResp<AccessTokenRespDto>();
        String apiKey = accessTokenReqDto.getApiKey();
        String apiSecret = accessTokenReqDto.getApiSecret();
        String issuerId = accessTokenReqDto.getIssuerId();
        try {
            ObjectIdentity rootObjectIdentity = new ObjectIdentity(ObjectIdentityType.parseFromValue(objectIdentityType), issuerId.getBytes());
            ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyByManagerId(rootObjectIdentity.encode());
            if (Tools.isNull(apiKeyDomain)) {
                throw new APIException(ExceptionEnum.API_KEY_NOT_EXIST);
            }
            if (!apiKey.equals(apiKeyDomain.getApiKey()) || !apiSecret.equals(apiKeyDomain.getApiSecret())) {
                throw new APIException(ExceptionEnum.API_KEY_ERROR);
            }

            ObjectIdentity issuerObjectIdentity = ObjectIdentity.decode(apiKeyDomain.getIssuerId());
            String issuerIdStr = HexFormat.byteToString(issuerObjectIdentity.getRawId());
            Map<String,String> tokenMap = new HashMap<>();
            tokenMap.put(Constants.API_KEY_MARK, apiKeyDomain.getApiKey());
            tokenMap.put(Constants.ISSUER_ID, issuerIdStr);
            String accessToken = JwtUtil.encode(tokenMap);

            redisUtil.setex(issuerId, accessToken, Constants.ACCESS_TOKEN_EXPIRES);
            AccessTokenRespDto accessTokenRespDto = new AccessTokenRespDto();
            accessTokenRespDto.setAccessToken(accessToken);
            accessTokenRespDto.setExpireIn(Constants.ACCESS_TOKEN_EXPIRES);
            dataResp.setData(accessTokenRespDto);
            dataResp.buildSuccessField();
        }catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        }catch (Exception e){
            logger.error("get access token error:{}.", e);
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }
}
