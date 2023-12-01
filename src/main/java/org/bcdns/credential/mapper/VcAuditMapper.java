package org.bcdns.credential.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.bcdns.credential.model.VcAuditDomain;
@Mapper
public interface VcAuditMapper {
    public int insert(VcAuditDomain vcAuditDomain);
    public VcAuditDomain getAuditDomain(String applyNo);
    public VcAuditDomain getVcIdByVcOwner(byte[] vcOwnerId);
}
