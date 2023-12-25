package org.bcdns.credential.service;

import org.bcdns.credential.mapper.VcRootMapper;
import org.bcdns.credential.model.VcRootDomain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class VcRootService {
    @Autowired
    private VcRootMapper vcRootMapper;

    public int insert(VcRootDomain vcRootDomain){
        return vcRootMapper.insert(vcRootDomain);
    }

    public VcRootDomain getVcRoot() {
        return vcRootMapper.getVcRoot();
    }
}
