package org.bcdns.credential.enums;

public enum StatusEnum {
    APPLYING(1, "待审核"),
    AUDIT_PASS(2, "审核通过"),
    AUDIT_REJECT(3, "审核不通过"),
    REVOKE(4, "吊销"),
    ;
    private Integer code;
    private String name;

    private StatusEnum(Integer code, String name) {
        this.code = code;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public Integer getCode() {
        return code;
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
