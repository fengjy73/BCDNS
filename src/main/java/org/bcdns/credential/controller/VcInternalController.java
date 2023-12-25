package org.bcdns.credential.controller;


import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.bcdns.credential.biz.VcInternalBiz;
import org.bcdns.credential.dto.req.VcApplyDetailReqDto;
import org.bcdns.credential.dto.req.VcApplyListReqDto;
import org.bcdns.credential.dto.req.VcIssueAuditReqDto;
import org.bcdns.credential.dto.req.VcRevocationReqDto;
import org.bcdns.credential.dto.resp.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/internal/vc")
public class VcInternalController {
    @Autowired
    private VcInternalBiz vcInternalBiz;

    @PostMapping(value = "/init")
    public DataResp<ApiKeyRespDto> init(){
        log.info("request url:{}","/vc/init");
        return vcInternalBiz.init();
    }

    @PostMapping(value = "/audit")
    public DataResp<VcIssueAuditRespDto> vcAudit(@RequestHeader("accessToken") String accessToken, @Valid @RequestBody VcIssueAuditReqDto vcAuditReqDto) {
        log.info("request url:{}******params:{}", "/vc/audit", JSONObject.toJSON(vcAuditReqDto));
        return vcInternalBiz.vcAudit(accessToken, vcAuditReqDto);
    }

    @PostMapping(value = "/list")
    public DataResp<VcApplyListRespDto> queryList(@RequestHeader("accessToken") String accessToken, @Valid @RequestBody VcApplyListReqDto requestBody) {
        log.info("request url:{}******params:{}", "/vc/list", JSONObject.toJSON(requestBody));
        return vcInternalBiz.queryList(accessToken, requestBody);
    }

    @PostMapping(value = "/detail")
    public DataResp<VcApplyDetailRespDto> queryDetail(@RequestHeader("accessToken") String accessToken, @Valid @RequestBody VcApplyDetailReqDto requestBody) {
        log.info("request url:{}******params:{}", "/vc/detail", JSONObject.toJSON(requestBody));
        return vcInternalBiz.queryDetail(accessToken, requestBody);
    }

    @PostMapping(value = "/revocation")
    public DataResp<VcRevocationRespDto> revocationVc(@RequestHeader("accessToken") String accessToken, @Valid @RequestBody VcRevocationReqDto reqDto) {
        log.info("request url:{}******params:{}", "/vc/revocation", JSONObject.toJSON(reqDto));
        return vcInternalBiz.revocationVc(accessToken, reqDto);
    }
}
