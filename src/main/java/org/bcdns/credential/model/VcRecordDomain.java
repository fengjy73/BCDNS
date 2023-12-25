package org.bcdns.credential.model;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class VcRecordDomain {
    private Integer id;
    private String applyNo;
    private byte[] content;
    private Integer credentialType;
    private Integer status;
    private String vcId;
    private byte[] vcData;
    private String publicKey;
    private byte[] userId;
    private long createTime;
    private long updateTime;
    private Integer isDownload;
}
