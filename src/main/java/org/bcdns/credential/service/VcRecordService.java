package org.bcdns.credential.service;

import org.bcdns.credential.dao.VcRecordDAO;
import org.bcdns.credential.dao.domain.VcRecordDomain;
import org.bcdns.credential.dao.domain.VcRecordListDomain;
import org.bcdns.credential.dto.req.VcApplyDetailReqDto;
import org.bcdns.credential.dto.req.VcApplyListReqDto;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;


@Service
public class VcRecordService {

    @Resource
    private VcRecordDAO vcRecordDAO;

    public int insert(VcRecordDomain vcRecordDomain){
       return vcRecordDAO.insert(vcRecordDomain);
    }

    public VcRecordDomain getVcRecord(String applyNo){
        return vcRecordDAO.getVcRecord(applyNo);
    }

    public VcRecordDomain getVcRecord4VcId(String vcId){
        return vcRecordDAO.getVcRecord4VcId(vcId);
    }

    public VcRecordDomain getVcRecord4UserId(byte[] vcId) {
        return vcRecordDAO.getVcRecord4UserId(vcId);
    }

    public int updateAuditPassStatus(String applyNo, Integer status, String vcId, byte[] vcData, long updateTime){
        return vcRecordDAO.updateAuditPassStatus(applyNo,status, vcId, vcData, updateTime);
    }

    public List<VcRecordListDomain> queryList(VcApplyListReqDto reqDto){
        return vcRecordDAO.queryList(reqDto);
    }

    public int queryListCount(VcApplyListReqDto reqDto){
        return vcRecordDAO.queryListCount(reqDto);
    }

    public VcRecordDomain queryDetail(VcApplyDetailReqDto reqDto){
        return vcRecordDAO.queryDetail(reqDto);
    }

    public Integer updateIsDownloadByVcId(Integer isDownload, String vcId) {
        return vcRecordDAO.updateIsDownloadByVcId(isDownload, vcId);
    }

    public Integer updateRevokeStatus(String credential, Integer status, long updateTime) {
        return vcRecordDAO.updateRevokeStatus(credential, status, updateTime);
    }
}
