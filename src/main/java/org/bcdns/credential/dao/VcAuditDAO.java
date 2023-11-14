package org.bcdns.credential.dao;

import net.paoding.rose.jade.annotation.DAO;
import net.paoding.rose.jade.annotation.SQL;
import org.bcdns.credential.dao.domain.VcAuditDomain;

@DAO
public interface VcAuditDAO {

    public static final String COLUMN = "id,apply_no,vc_id,status,audit_id,vc_owner_id,reason,create_time,update_time";

    @SQL("INSERT INTO vc_audit ($COLUMN) VALUES (:1.id,:1.applyNo,:1.vcId,:1.status,:1.auditId,:1.vcOwnerId,:1.reason,:1.createTime,0)")
    public int insert(VcAuditDomain vcAuditDomain);

    @SQL("select $COLUMN from vc_audit where apply_no=:1")
    public VcAuditDomain getAuditDomain(String applyNo);

    @SQL("select $COLUMN from vc_audit where vc_owner_id=:1")
    public VcAuditDomain getVcIdByVcOwner(byte[] vcOwnerId);
}