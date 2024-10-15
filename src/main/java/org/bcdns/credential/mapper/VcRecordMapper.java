package org.bcdns.credential.mapper;

import org.bcdns.credential.model.VcRecordDomain;
import org.bcdns.credential.model.VcRecordListDomain;
import org.bcdns.credential.dto.req.VcApplyDetailReqDto;
import org.bcdns.credential.dto.req.VcApplyListReqDto;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface VcRecordMapper {
    public int insert(VcRecordDomain vcRecordDomain);
    public VcRecordDomain getVcRecord(String applyNo);
    public VcRecordDomain getVcRecord4VcId(String vcId);
    public VcRecordDomain getVcRecord4UserId(byte[] userId);
    public VcRecordDomain getVcRecord4OwnerPubKey(String ownerPublicKey);
    public int updateAuditPassStatus(VcRecordDomain vcRecordDomain);
    public List<VcRecordListDomain> queryList(VcApplyListReqDto reqDto);
    public int queryListCount(VcApplyListReqDto reqDto);
    public VcRecordDomain queryDetail(VcApplyDetailReqDto reqDto);
    public Integer updateIsDownloadByVcId(VcRecordDomain vcRecordDomain);
    public Integer updateRevokeStatus(VcRecordDomain vcRecordDomain);
}
