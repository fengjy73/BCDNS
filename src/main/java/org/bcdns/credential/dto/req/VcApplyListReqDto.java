package org.bcdns.credential.dto.req;

import lombok.Data;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import static org.bcdns.credential.common.constant.MessageConstant.*;

@Data
public class VcApplyListReqDto extends PageReqDto {
    @NotNull(message = DESC_VALID_NULL)
    @Size(min = 1, max = 4, message = DESC_VALID_BYTE_LENGTH)
    private Integer[] status;
}
