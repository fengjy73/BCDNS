package org.bcdns.credential.dto.req;

import lombok.Data;

@Data
public class VcPTCTrustRootReqDto {
    private byte[] ptcOid;
    private byte[] content;
}
