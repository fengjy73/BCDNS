package org.bcdns.credential.controller;

import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.bcdns.credential.biz.AuthBiz;
import org.bcdns.credential.dto.req.AccessTokenReqDto;
import org.bcdns.credential.dto.resp.AccessTokenRespDto;
import org.bcdns.credential.dto.resp.DataResp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/internal/vc")
public class AuthController {
    @Autowired
    private AuthBiz authBiz;

    @PostMapping(value = "/get/accessToken")
    public DataResp<AccessTokenRespDto> getAccessToken(@Valid @RequestBody AccessTokenReqDto accessTokenReqDto) {
        log.info("request url:{}******params:{}","/vc/get/accessToken", JSONObject.toJSON(accessTokenReqDto));
        return authBiz.getAccessToken(accessTokenReqDto);
    }
}
