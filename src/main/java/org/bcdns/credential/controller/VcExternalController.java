package org.bcdns.credential.controller;


import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.bcdns.credential.biz.VcExternalBiz;
import org.bcdns.credential.dto.req.QueryStatusReqDto;
import org.bcdns.credential.dto.req.VcApplyReqDto;
import org.bcdns.credential.dto.req.VcInfoReqDto;
import org.bcdns.credential.dto.resp.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/external/vc")
public class VcExternalController {
    @Autowired
    private VcExternalBiz vcExternalBiz;

    @PostMapping(value = "/apply")
    public DataResp<VcApplyRespDto> vcApply(@Valid @RequestBody VcApplyReqDto vcApplyReqDto) {
        log.info("request url:{}******params:{}", "/vc/apply", JSONObject.toJSON(vcApplyReqDto));
        return vcExternalBiz.vcApply(vcApplyReqDto);
    }

    @PostMapping(value = "/apply/status")
    public DataResp<QueryStatusRespDto> applyStatus(@Valid @RequestBody QueryStatusReqDto reqDto){
        log.info("request url:{}******params:{}", "/vc/apply/status", JSONObject.toJSON(reqDto));
        return vcExternalBiz.applyStatus(reqDto);
    }

    @PostMapping(value = "/status")
    public DataResp<QueryStatusRespDto> vcStatus(@Valid @RequestBody VcInfoReqDto reqDto){
        log.info("request url:{}******params:{}", "/vc/status", JSONObject.toJSON(reqDto));
        return vcExternalBiz.vcStatus(reqDto);
    }

    @PostMapping(value = "/download")
    public DataResp<VcInfoRespDto> vcDownload(@Valid @RequestBody VcInfoReqDto reqDto){
        log.info("request url:{}******params:{}", "/vc/download", JSONObject.toJSON(reqDto));
        return vcExternalBiz.vcDownload(reqDto);
    }

    @PostMapping(value = "/root")
    public DataResp<VcRootRespDto> getVcRoot(){
        return vcExternalBiz.getVcRoot();
    }
}
