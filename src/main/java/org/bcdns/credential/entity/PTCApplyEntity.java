package org.bcdns.credential.entity;

import lombok.Data;

@Data
public class PTCApplyEntity {
    private String name;
    private Integer type;
    private byte[] id;
    private String publicKey;
}
