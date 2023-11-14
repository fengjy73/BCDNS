package org.bcdns.credential.dao;

import net.paoding.rose.jade.annotation.DAO;
import net.paoding.rose.jade.annotation.SQL;
import org.bcdns.credential.dao.domain.VcRecordListDomain;
import org.bcdns.credential.dto.req.VcApplyDetailReqDto;
import org.bcdns.credential.dto.req.VcApplyListReqDto;
import org.bcdns.credential.dao.domain.VcRecordDomain;

import java.util.List;


@DAO
public interface VcRecordDAO {

    public static final String COLUMN = "id,apply_no,content,credential_type," +
            "status,vc_id,vc_data,public_key,user_id,create_time,update_time,is_download";

    @SQL("INSERT INTO vc_record ($COLUMN) VALUES (:1.id,:1.applyNo,:1.content,:1.credentialType," +
            ":1.status,:1.vcId,:1.vcData,:1.publicKey,:1.userId,:1.createTime,0,:1.isDownload)")
    public int insert(VcRecordDomain vcRecordDomain);

    @SQL("select  $COLUMN from vc_record where apply_no = :1  ORDER BY create_time DESC LIMIT 1")
    public VcRecordDomain getVcRecord(String applyNo);

    @SQL("select $COLUMN from vc_record where vc_id = :1  ORDER BY create_time DESC LIMIT 1")
    public VcRecordDomain getVcRecord4VcId(String vcId);

    @SQL("select $COLUMN from vc_record where user_id = :1  ORDER BY create_time DESC LIMIT 1")
    public VcRecordDomain getVcRecord4UserId(byte[] userId);

    @SQL("UPDATE vc_record SET `status` = :2,`vc_id` = :3,`vc_data` = :4, `update_time` = :5 WHERE apply_no = :1")
    public int updateAuditPassStatus(String applyNo, Integer status, String vcId, byte[] vcData, long updateTime);

    @SQL("SELECT vr.apply_no, vr.vc_id credential_id, vr.`status`, vr.user_id, vr.create_time, " +
            "vr.credential_type, vr.update_time audit_time, vr.is_download " +
            "FROM vc_record vr WHERE 1 = 1  #if(:1.status != null) {and vr.status in (:1.status)} " +
            "order by vr.create_time DESC limit :1.startNum,:1.pageSize")
    public List<VcRecordListDomain> queryList(VcApplyListReqDto reqDto);

    @SQL("SELECT COUNT(1) FROM vc_record vr WHERE 1 = 1 #if(:1.status != null) {and vr.status in (:1.status)} ")
    public int queryListCount(VcApplyListReqDto reqDto);

    @SQL("SELECT $COLUMN from vc_record WHERE 1=1 " +
            " #if(:1.applyNo != null && :1.applyNo != ''){ AND apply_no = :1.applyNo}" +
            " #if(:1.credentialId != null && :1.credentialId != ''){ AND vc_id = :1.credentialId}")
    public VcRecordDomain queryDetail(VcApplyDetailReqDto reqDto);

    @SQL("UPDATE vc_record SET is_download = :1,`update_time` = NOW()  WHERE vc_id = :2")
    public Integer updateIsDownloadByVcId(Integer isDownload, String vcId);

    @SQL("UPDATE vc_record SET `status` = :2,`update_time` = :3  WHERE vc_id = :1")
    public Integer updateRevokeStatus(String credentialId, Integer status, long updateTime);
}
