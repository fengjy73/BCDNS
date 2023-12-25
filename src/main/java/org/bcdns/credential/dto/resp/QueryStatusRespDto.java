package org.bcdns.credential.dto.resp;

import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import lombok.Data;
import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.Range;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

import static org.bcdns.credential.common.constant.MessageConstant.*;

@Data
public class QueryStatusRespDto {
    @Range(min = 1, max = 4, message = DESC_VALID_NUMBER)
    private Integer status;

    @Length(max = 64, message = DESC_VALID_STRING)
    private String credentialId;

    private ObjectIdentity userId;
}
