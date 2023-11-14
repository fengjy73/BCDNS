package org.bcdns.credential.dao.domain;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;


@Data
@NoArgsConstructor
public class VcAuditDomain {
    private Integer id;
    private String applyNo;
    private String  vcId;
    private Integer status;
    private byte[] auditId;
    private byte[] vcOwnerId;
    private String reason;
    private long createTime;
    private long updateTime;
}
