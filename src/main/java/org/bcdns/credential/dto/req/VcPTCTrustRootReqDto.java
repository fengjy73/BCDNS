package org.bcdns.credential.dto.req;

import lombok.Data;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import static org.bcdns.credential.common.constant.MessageConstant.DESC_VALID_BYTE;
import static org.bcdns.credential.common.constant.MessageConstant.DESC_VALID_NULL;

@Data
public class VcPTCTrustRootReqDto {
    @NotNull(message = DESC_VALID_NULL)
    @Size(min = 1, message= DESC_VALID_BYTE)
    private byte[] ptcTrustRoot;
}
