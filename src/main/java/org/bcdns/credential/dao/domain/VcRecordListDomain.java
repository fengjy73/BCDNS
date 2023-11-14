package org.bcdns.credential.dao.domain;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class VcRecordListDomain {
    private String applyNo;
    private String credentialId;
    private String status;
    private byte[] userId;
    private Long createTime;
    private Integer credentialType;
    private Long auditTime;
    private Integer isDownload;
}
