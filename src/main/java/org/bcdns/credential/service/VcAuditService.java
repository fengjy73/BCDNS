package org.bcdns.credential.service;

import org.bcdns.credential.dao.VcAuditDAO;
import org.bcdns.credential.dao.domain.VcAuditDomain;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
@Service
public class VcAuditService {

    @Resource
    private VcAuditDAO vcAuditDAO;

    public int insertAudit(VcAuditDomain vcAuditDomain){
       return vcAuditDAO.insert(vcAuditDomain);
    }

    public VcAuditDomain getAuditDomain(String applyNo){
        return vcAuditDAO.getAuditDomain(applyNo);
    }

    public VcAuditDomain getVcIdByVcOwner(byte[] vcOwnerId) {
        return vcAuditDAO.getVcIdByVcOwner(vcOwnerId);
    }
}
