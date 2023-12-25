package org.bcdns.credential.model;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class VcRecordListDomain {
    private String applyNo;
    private String credentialId;
    private Integer status;
    private byte[] userId;
    private long createTime;
    private Integer credentialType;
    private long auditTime;
    private Integer isDownload;
}
