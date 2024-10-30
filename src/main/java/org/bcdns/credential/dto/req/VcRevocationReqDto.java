package org.bcdns.credential.dto.req;

import lombok.Data;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

import static org.bcdns.credential.common.constant.MessageConstant.*;

@Data
public class VcRevocationReqDto {
    @NotBlank(message = DESC_VALID_NULL)
    @Pattern(regexp = PATTERN_MAIN_BID, message = VALID_MAIN_BID_FORMAT)
    private String credentialId;

    @NotBlank(message = DESC_VALID_NULL)
    @Length(max = 1024, message = DESC_VALID_STRING_LENGTH)
    private String remark;

}
