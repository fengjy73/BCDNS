package org.bcdns.credential.service;


import org.bcdns.credential.dto.req.VcApplyDetailReqDto;
import org.bcdns.credential.dto.req.VcApplyListReqDto;
import org.bcdns.credential.mapper.VcRecordMapper;
import org.bcdns.credential.model.VcRecordDomain;
import org.bcdns.credential.model.VcRecordListDomain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VcRecordService {

    @Autowired
    private VcRecordMapper vcRecordMapper;

    public int insert(VcRecordDomain vcRecordDomain){
       return vcRecordMapper.insert(vcRecordDomain);
    }

    public VcRecordDomain getVcRecord(String applyNo){
        return vcRecordMapper.getVcRecord(applyNo);
    }

    public VcRecordDomain getVcRecord4VcId(String vcId){
        return vcRecordMapper.getVcRecord4VcId(vcId);
    }

    public VcRecordDomain getVcRecord4UserId(byte[] vcId) {
        return vcRecordMapper.getVcRecord4UserId(vcId);
    }

    public int updateAuditPassStatus(VcRecordDomain vcRecordDomain){
        return vcRecordMapper.updateAuditPassStatus(vcRecordDomain);
    }

    public List<VcRecordListDomain> queryList(VcApplyListReqDto reqDto){
        return vcRecordMapper.queryList(reqDto);
    }

    public int queryListCount(VcApplyListReqDto reqDto){
        return vcRecordMapper.queryListCount(reqDto);
    }

    public VcRecordDomain queryDetail(VcApplyDetailReqDto reqDto){
        return vcRecordMapper.queryDetail(reqDto);
    }

    public Integer updateIsDownloadByVcId(VcRecordDomain vcRecordDomain) {
        return vcRecordMapper.updateIsDownloadByVcId(vcRecordDomain);
    }

    public Integer updateRevokeStatus(VcRecordDomain vcRecordDomain) {
        return vcRecordMapper.updateRevokeStatus(vcRecordDomain);
    }
}
