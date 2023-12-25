package org.bcdns.credential.service;


import org.bcdns.credential.mapper.VcAuditMapper;
import org.bcdns.credential.model.VcAuditDomain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
@Service
public class VcAuditService {

    @Autowired
    private VcAuditMapper vcAuditMapper;

    public int insertAudit(VcAuditDomain vcAuditDomain){
       return vcAuditMapper.insert(vcAuditDomain);
    }

    public VcAuditDomain getAuditDomain(String applyNo){
        return vcAuditMapper.getAuditDomain(applyNo);
    }

    public VcAuditDomain getVcIdByVcOwner(byte[] vcOwnerId) {
        return vcAuditMapper.getVcIdByVcOwner(vcOwnerId);
    }
}
