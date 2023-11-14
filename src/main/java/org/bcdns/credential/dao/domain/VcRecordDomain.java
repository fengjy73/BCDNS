package org.bcdns.credential.dao.domain;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;


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
    private Long createTime;
    private Long updateTime;
    private Integer isDownload;
}
