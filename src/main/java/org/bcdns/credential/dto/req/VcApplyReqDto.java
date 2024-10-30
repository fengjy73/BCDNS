package org.bcdns.credential.dto.req;

import lombok.Data;
import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.Range;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import static org.bcdns.credential.common.constant.MessageConstant.*;

@Data
public class VcApplyReqDto {

    @NotNull(message = DESC_VALID_NULL)
    @Size(min = 1, message= DESC_VALID_BYTE)
    private byte[] content;

    @NotNull(message = DESC_VALID_NULL)
    @Range(min = 1, max = 3, message = DESC_VALID_NUMBER)
    private Integer credentialType;

    @NotNull(message = DESC_VALID_NULL)
    private String publicKey;

    private String signAlgo;

    @NotNull(message = DESC_VALID_NULL)
    @Size(min = 1, message= DESC_VALID_BYTE)
    private byte[] sign;

}

