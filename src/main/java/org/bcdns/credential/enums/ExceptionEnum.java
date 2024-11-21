package org.bcdns.credential.enums;

import lombok.Getter;

@Getter
public enum ExceptionEnum {
    SUCCESS(0, "success"),

    PARAME_ERROR(1, "invalid param"),

    SYS_ERROR(100100, "system error"),

    PLATFORM_REPEAT_INIT(100101, "server has inited"),

    API_KEY_NOT_EXIST(100102, "api-key is not existed"),

    API_KEY_ERROR(100103, "api-key is wrong"),

    ACCESS_TOKEN_INVALID(100104, "access token is invalid"),

    SIGN_ERROR(100105, "failed to verify sign"),

    CREDENTIAL_APPLY_NOT_EXIST(100106, "credential apply is not existed"),

    CREDENTIAL_BUILD_ERROR(100107, "failed to create credential"),

    CREDENTIAL_AUDITED(100108, "credential apply ha been audited"),

    SUBMIT_TX_ERROR(100109, "failed to submit tx"),

    CREDENTIAL_NOT_EXIST(100110, "credential is not existed"),

    CREDENTIAL_IS_REVOKE(100111, "credential has been revoked"),

    CREDENTIAL_IS_DOWNLOAD(100112, "credential has been downloaded"),

    PRIVATE_KEY_IS_INVALID(100113, "private key is invalid"),

    PTCTRUSTROOT_SIGN_VERIFY_ERROR(100114, "ptc trust root sign verify error"),

    REGISTER_PTCTRUSTROOT_ERROR(100115, "register ptc trust root error"),

    REGISTER_TPBTA_ERROR(100116, "register ptba error"),

    TPBTA_SIGN_VERIFY_ERROR(100117, "tpbta verify error"),

    TPBTA_BELONG_TYPE_ERROR(100118, "tpbta belong type error"),

    KEYTYPE_ERROR(100119, "key type error"),

    CONTRACT_QUERY_ERROR(100120, "contract query error"),

    QUERY_RESP_PARAM_ERROR(100121, "query param error"),

    CONTRACT_INVOKE_ERROR(100122, "contract invoke error"),

    TPBTA_LEVEL_ERROR(100123, "tpbta level error"),

    FAILED_TO_DECRYPT_PRIVATE(100124, "failed to decrypt private key"),
    ;
    private final Integer errorCode;
    private final String message;

    ExceptionEnum(Integer errorCode, String message) {
        this.errorCode = errorCode;
        this.message = message;
    }
}
