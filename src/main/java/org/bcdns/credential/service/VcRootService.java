package org.bcdns.credential.service;

import org.bcdns.credential.dao.VcRootDAO;
import org.bcdns.credential.dao.domain.VcRootDomain;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class VcRootService {
    @Resource
    private VcRootDAO vcRootDAO;

    public int insert(VcRootDomain vcRootDomain){
        return vcRootDAO.insert(vcRootDomain);
    }

    public VcRootDomain getVcRoot() {
        return vcRootDAO.getVcRoot();
    }
}
