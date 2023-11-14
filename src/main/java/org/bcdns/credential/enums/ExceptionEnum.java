package org.bcdns.credential.enums;

public enum ExceptionEnum {
    SUCCESS(0, "成功"),
    PARAME_ERROR(1, "无效参数"),

    PLATFORM_REPEAT_INIT(2, "Platform repeated initialization"),

    API_KEY_NOT_EXIST(3, "api-key not exist"),

    API_KEY_ERROR(4, "api-key error"),
    ACCESS_TOKEN_INVALID(5, "access token invalid"),

    SIGN_ERROR(6, "sign error"),

    CREDENTIAL_APPLY_NOT_EXIST(7, "credential apply record not exist"),

    CREDENTIAL_BUILD_ERROR(8, "credential build error"),

    CREDENTIAL_AUDITED(9, "credential has been audited"),

    SUBMIT_TX_ERROR(10, "submit tx error"),

    CREDENTIAL_NOT_EXIST(10, "credential not exist"),

    CREDENTIAL_IS_REVOKE(10, "credential is revoke"),

    SYS_ERROR(400000, "系统内部错误"),
    BASE_CREDENTIAL_HOLDED_OTHER_ERROR(100100, "您已获取其它可信凭证, 无法申请此凭证"),
    BASE_CREDENTIAL_HOLDED_ERROR(100101, "您已拥有了该数字凭证, 无需重复申请"),
    CREDENTIAL_APLLY_PENDING_ERROR(100102, "您已申请可信凭证, 请耐心等待审核结果"),
    CREDENTIAL_CUSTOMER_APLLY_PENDING_ERROR(100103, "您已申请该数字凭证, 请耐心等待审核结果"),
    CREDENTIAL_PAYLOAD_NOT_EXIST(100003, "凭证payload不存在"),
    CREDENTIAL_TEMPLATE_NOT_EXIST(100005, "不支持的模板类型"),
    APPLY_AUDITED_ERROR(100081, "当前申请已经审核，请勿重复提交"),
    APPLY_REVOCAT_ERROR(100082, "当前凭证已吊销，请勿重复提交"),
    REVOCATION_CONTRACT_NOT_EXIST(100106,"吊销合约不存在"),
    CREDENTIAL_APLLY_TYPE_PERSONAL_ERROR(100107,"您曾申请过星火个人可信认证，不能再申请其它类型星火可信认证"),
    CREDENTIAL_APLLY_TYPE_COMPANY_ERROR(100108,"您曾申请过星火企业可信认证，不能再申请其它类型星火可信认证"),
    CREDENTIAL_APLLY_TYPE_GOVERNMENT_ERROR(100109,"您曾申请过星火政府可信认证，不能再申请其它类型星火可信认证"),

    TEMPLATLE_COMMITED_ERROR(100006, "凭证模板已经创建，请勿重复提交"),
    AUDIT_AUTH_BLOB_EXIST(100007, "审核认证blob不存在"),
    BID_AUTH_LOGIN_ERROR(100008, "BID签名错误"),
    VP_NON_SUPPORT(100009, "不支持的证书验证"),

    VP_CONTENT_NOT_DICT(100010, "断言语句不是字典类型"),
    VP_CONTENT_NOT_VCFORMAT(100011, "content存在证书没有定义的字段"),
    VP_JWS_INCORRECT(100012, "验证请求jws不正确"),
    VP_COMPOSE_ERROR(100013, "composeType 错误"),
    VP_VERIFY_NO_PASS(100014, "验证不通过"),
    VP_VERIFYER_NOT_MATCHING_ERROR(100115, "验证方不匹配"),
    VP_CRED_INVALID_ERROR(100116, "证书已过期"),
    VP_CRED_STATUS_INVALID_ERROR(100117, "凭证状态无效"),
    VP_VERIFY_SIGN_ERROR(100118, "发证方验签失败"),
    VP_VERIFY_HASH_ERROR(100119, "hash验证失败"),
    QUERY_BID_PUBLICKEY_ERROR(100120, "查询公钥失败"),

    AUTH_BID_LOGIN_ERROR(100015, "无权限访问"),
    UPLOAD_FILE_ERROR(100016, "上传文件异常"),

    USER_TRUSTED_COMMITED_ERROR(100017, "用户已经授权可信认证"),

    USER_NOT_TRUSTED(100018, "该用户不可信，请完善可信认证信息"),
    USER_RECORD_SIGNBLOB_ERROR(100019, "singBlob签名无效"),
    AUDI_ISSURE_NOT_TRUSTED(100085, "该企业不可信，不能进行通过操作"),

    OCR_INVALID(100020, "无效的营业执照文件"),
    OCR_SERVICE_ERROR(100021, "OCR接口异常"),
    OCR_TWO_ERROR(100022, "身份二要素接口异常"),

    AREA_CODE_ERROR(100023, "地区编号不存在"),

    ISSUER_VC_BLOB_ERROR(100024, "颁发凭证获取blob异常"),
    ISSUER_VC_TX_SUBMIT_ERROR(100025, "颁发凭证提交交易异常"),
    REVOCAT_VC_TX_SUBMIT_ERROR(100029, "吊销凭证提交交易异常"),

    TX_SIGN_ERROR(100026, "交易签名错误"),
    PUBLICKEY_PARAME_ERROR(100027, "无效的公钥"),
    CREDENTIAL_ID_NOT_EXIST(100028, "凭证不存在"),
    CREDENTIAL_IS_DOWNLOAD(100030, "凭证已下载"),
    CREDENTIAL_USER_INCORRECT(100031, "凭证与用户不符"),
    TX_RECHARGEGAS_ERROR(50014,"充值失败"),
    REMARK_LENGTH_ERROR(50015,"备注不能超过256字符"),
    TX_INSUFFICIENT_FUNDS_ERROR(100,"账户余额不足，交易失败"),
    TX_SIGNATURE_WEIGHT_ERROR(93,"签名权重不足，请在身份授权管理进行分配"),

    QUERY_COCHAIN_ERROR(100030,"查询上链服务异常"),
    COMPANY_CRT_NOT_FIND_ERROR(400001,"为查询到"),
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
