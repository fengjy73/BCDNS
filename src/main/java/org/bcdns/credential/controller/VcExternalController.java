package org.bcdns.credential.controller;


import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.bcdns.credential.biz.VcExternalBiz;
import org.bcdns.credential.dto.req.*;
import org.bcdns.credential.dto.resp.*;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/vc")
public class VcExternalController {
    @Resource
    private VcExternalBiz vcExternalBizBiz;

    @PostMapping(value = "/apply")
    public DataResp<VcApplyRespDto> vcApply(@Valid @RequestBody VcApplyReqDto vcApplyReqDto){
        log.info("request url:{}******params:{}","/vc/apply", JSONObject.toJSON(vcApplyReqDto));
        return vcExternalBizBiz.vcApply(vcApplyReqDto);
    }

    @PostMapping(value = "/apply/status")
    public DataResp<QueryStatusRespDto> applyStatus(@Valid @RequestBody QueryStatusReqDto reqDto){
        log.info("request url:{}******params:{}","/vc/apply/status", JSONObject.toJSON(reqDto));
        return vcExternalBizBiz.applyStatus(reqDto);
    }

    @PostMapping(value = "/status")
    public DataResp<QueryStatusRespDto> vcStatus(@Valid @RequestBody VcInfoReqDto reqDto){
        log.info("request url:{}******params:{}","/vc/status", JSONObject.toJSON(reqDto));
        return vcExternalBizBiz.vcStatus(reqDto);
    }

    @PostMapping(value = "/download")
    public DataResp<VcInfoRespDto> vcDownload(@Valid @RequestBody VcInfoReqDto reqDto){
        log.info("request url:{}******params:{}","/vc/download", JSONObject.toJSON(reqDto));
        return vcExternalBizBiz.vcDownload(reqDto);
    }

    @PostMapping(value = "/root")
    public DataResp<VcRootRespDto> getVcRoot(){
        return vcExternalBizBiz.getVcRoot();
    }
}
