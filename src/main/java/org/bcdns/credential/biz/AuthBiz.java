package org.bcdns.credential.biz;

import org.bcdns.credential.common.constant.Constants;
import org.bcdns.credential.common.utils.JwtUtil;
import org.bcdns.credential.common.utils.RedisUtil;
import org.bcdns.credential.common.utils.Tools;
import org.bcdns.credential.dto.req.AccessTokenReqDto;
import org.bcdns.credential.dto.resp.AccessTokenRespDto;
import org.bcdns.credential.dto.resp.DataResp;
import org.bcdns.credential.enums.ExceptionEnum;
import org.bcdns.credential.exception.APIException;
import org.bcdns.credential.model.ApiKeyDomain;
import org.bcdns.credential.service.ApiKeyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
@Component
public class AuthBiz {

    private static final Logger logger = LoggerFactory.getLogger(AuthBiz.class);
    @Autowired
    private ApiKeyService apiKeyService;

    @Autowired
    private RedisUtil redisUtil;

    public DataResp<AccessTokenRespDto> getAccessToken(AccessTokenReqDto accessTokenReqDto) {
        DataResp<AccessTokenRespDto> dataResp = new DataResp<AccessTokenRespDto>();
        String apiKey = accessTokenReqDto.getApiKey();
        String apiSecret = accessTokenReqDto.getApiSecret();
        String issuerId = accessTokenReqDto.getIssuerId();
        try {
            ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyByManagerId(issuerId);
            if (Tools.isNull(apiKeyDomain)) {
                throw new APIException(ExceptionEnum.API_KEY_NOT_EXIST);
            }
            if (!apiKey.equals(apiKeyDomain.getApiKey()) || !apiSecret.equals(apiKeyDomain.getApiSecret())) {
                throw new APIException(ExceptionEnum.API_KEY_ERROR);
            }

            String issuer = apiKeyDomain.getIssuerId();
            Map<String,String> tokenMap = new HashMap<>();
            tokenMap.put(Constants.API_KEY_MARK, apiKeyDomain.getApiKey());
            tokenMap.put(Constants.ISSUER_ID, issuer);
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
