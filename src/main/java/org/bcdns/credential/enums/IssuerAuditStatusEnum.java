package org.bcdns.credential.enums;

public enum IssuerAuditStatusEnum {
    ISSUER_AUDITING(0, "审核中"),
    ISSUER_AUDIT_PASS(1,"审核通过"),
    ISSUER_AUDIT_NOT_PASS(2, "审核未通过");
    private Integer code;
    private String name;

    private IssuerAuditStatusEnum(Integer code, String name) {
        this.code = code;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public Integer getCode() {
        return code;
    }
}
