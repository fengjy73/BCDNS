package org.bcdns.credential.dto.req;

import lombok.Data;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

import static org.bcdns.credential.common.constant.MessageConstant.*;

@Data
public class VcInfoReqDto {
    @NotBlank(message = DESC_VALID_NULL)
    @Length(min = 1, max = 64, message = DESC_VALID_STRING)
    @Pattern(regexp = PATTERN_MAIN_BID, message = VALID_MAIN_BID_FORMAT)
    private String credentialId;
}
