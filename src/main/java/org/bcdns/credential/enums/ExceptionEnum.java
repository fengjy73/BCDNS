package org.bcdns.credential.enums;

public enum ExceptionEnum {
    SUCCESS(0, "成功"),
    PARAME_ERROR(1, "无效参数"),

    SYS_ERROR(100100, "系统内部错误"),

    PLATFORM_REPEAT_INIT(100101, "Platform repeated initialization"),

    API_KEY_NOT_EXIST(100102, "api-key not exist"),

    API_KEY_ERROR(100103, "api-key error"),
    ACCESS_TOKEN_INVALID(100104, "access token invalid"),

    SIGN_ERROR(100105, "sign error"),

    CREDENTIAL_APPLY_NOT_EXIST(100106, "credential apply record not exist"),

    CREDENTIAL_BUILD_ERROR(100107, "credential build error"),

    CREDENTIAL_AUDITED(100108, "credential has been audited"),

    SUBMIT_TX_ERROR(100109, "submit tx error"),

    CREDENTIAL_NOT_EXIST(100110, "credential not exist"),

    CREDENTIAL_IS_REVOKE(100111, "credential is revoke"),

    CREDENTIAL_IS_DOWNLOAD(100113, "凭证已下载"),

    ;
    private Integer errorCode;
    private String message;

    ExceptionEnum(Integer errorCode, String message) {
        this.errorCode = errorCode;
        this.message = message;
    }

    public Integer getErrorCode() {
        return errorCode;
    }


    public String getMessage() {
        return message;
    }

}
