package org.bcdns.credential.entity;

import lombok.Data;

@Data
public class DomainNameApplyEntity {
    private Integer domainNameType;
    private String domainName;
    private byte[] id;
    private String publicKey;
}
