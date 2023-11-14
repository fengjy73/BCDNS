package org.bcdns.credential.dao;

import net.paoding.rose.jade.annotation.DAO;
import net.paoding.rose.jade.annotation.SQL;

import org.bcdns.credential.dao.domain.VcRootDomain;

@DAO
public interface VcRootDAO {
    public static final String COLUMN = "id,vc_root";

    @SQL("INSERT INTO vc_root ($COLUMN) VALUES (:1.id,:1.vcRoot)")
    public int insert(VcRootDomain vcRootDomain);

    @SQL("select $COLUMN from vc_root where id = 1")
    public VcRootDomain getVcRoot();
}
