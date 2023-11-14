package org.bcdns.credential.redis;

import lombok.Data;

import java.util.Date;


@Data
public class VcAuditPayloadRedis {
    private String applyNo;
    private String vcId;
    private String auditBid;
    private String publicKey;
    private String signStr;
    private String header;
    private String vcData;
    private String auditRemark;
    private Integer status;
    private String alg;
    private String issuanceDate;
    private String vcContent;
}
