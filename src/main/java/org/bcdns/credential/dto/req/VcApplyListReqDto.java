package org.bcdns.credential.dto.req;

import lombok.Data;

import java.util.List;

@Data
public class VcApplyListReqDto extends PageReqDto {
    private Integer[] status;
}
