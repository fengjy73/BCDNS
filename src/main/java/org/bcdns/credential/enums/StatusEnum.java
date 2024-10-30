package org.bcdns.credential.enums;

import lombok.Getter;

@Getter
public enum StatusEnum {
    APPLYING(1, "待审核"),
    AUDIT_PASS(2, "审核通过"),
    AUDIT_REJECT(3, "审核不通过"),
    REVOKE(4, "吊销"),
    ;
    private final Integer code;
    private final String name;

    StatusEnum(Integer code, String name) {
        this.code = code;
        this.name = name;
    }

    public static String getValueByCode(Integer code) {
        for (StatusEnum credentialStatus : StatusEnum.values()) {
            if (code.equals(credentialStatus.getCode())) {
                return credentialStatus.getName();
            }
        }
        return null;
    }
}
