package org.bcdns.credential.enums;

import lombok.Getter;

@Getter
public enum ExceptionEnum {
    SUCCESS(0, "成功"),

    PARAME_ERROR(1, "无效参数"),

    SYS_ERROR(100100, "系统错误"),

    PLATFORM_REPEAT_INIT(100101, "服务重复初始化"),

    API_KEY_NOT_EXIST(100102, "api-key不存在"),

    API_KEY_ERROR(100103, "api-key错误"),

    ACCESS_TOKEN_INVALID(100104, "access token无效"),

    SIGN_ERROR(100105, "验签失败"),

    CREDENTIAL_APPLY_NOT_EXIST(100106, "凭证申请不存在"),

    CREDENTIAL_BUILD_ERROR(100107, "凭证创建失败"),

    CREDENTIAL_AUDITED(100108, "凭证申请已经被审核"),

    SUBMIT_TX_ERROR(100109, "提交交易失败"),

    CREDENTIAL_NOT_EXIST(100110, "凭证不存在"),

    CREDENTIAL_IS_REVOKE(100111, "凭证被注销"),

    CREDENTIAL_IS_DOWNLOAD(100112, "凭证已下载"),

    PRIVATE_KEY_IS_INVALID(100113, "无效私钥"),

    FAILED_TO_DECRYPT_PRIVATE(100114, "解析密文私钥失败"),

    PTCTRUSTROOT_SIGN_VERIFY_ERROR(100114, "ptctrustroot sign verify error"),

    REGISTER_PTCTRUSTROOT_ERROR(100115, "register ptctrustroot error"),

    REGISTER_TPBTA_ERROR(100116, "register ptba error"),

    TPBTA_SIGN_VERIFY_ERROR(100117, "tpbta verify error"),

    TPBTA_BELONG_TYPE_ERROR(100118, "tpbta belong type error"),

    KEYTYPE_ERROR(100119, "keytype error"),

    CONTRACT_QUERY_ERROR(100120, "contract query error"),

    QUERY_RESP_PARAM_ERROR(100121, "query param error"),

    CONTRACT_INVOKE_ERROR(100122, "contract invoke error"),

    TPBTA_LEVEL_ERROR(100123, "tpbta level error"),
    ;
    private final Integer errorCode;
    private final String message;

    ExceptionEnum(Integer errorCode, String message) {
        this.errorCode = errorCode;
        this.message = message;
    }
}
