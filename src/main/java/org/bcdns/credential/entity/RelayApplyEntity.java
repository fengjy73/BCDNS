package org.bcdns.credential.entity;

import lombok.Data;

@Data
public class RelayApplyEntity {
    private String name;
    private byte[] id;
    private String publicKey;
}
