package org.bcdns.credential.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.bcdns.credential.model.VcRootDomain;

@Mapper
public interface VcRootMapper {
    public int insert(VcRootDomain vcRootDomain);
    public VcRootDomain getVcRoot();
}
