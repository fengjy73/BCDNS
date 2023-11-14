package org.bcdns.credential.exception;


import org.bcdns.credential.enums.ExceptionEnum;

public class APIException extends RuntimeException{
    private Integer errorCode;
    private String errorMessage;

    public APIException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = ExceptionEnum.SYS_ERROR.getErrorCode();
        this.errorMessage = message;
    }

    public APIException(Throwable cause) {
        super(cause);
        this.errorCode = ExceptionEnum.SYS_ERROR.getErrorCode();
        this.errorMessage = ExceptionEnum.SYS_ERROR.getMessage();
    }

    public APIException(Integer errorCode, String message){
       super(message);
       this.errorCode = errorCode;
       this.errorMessage = message;
    }

    public APIException(ExceptionEnum errorEnum) {
        this(errorEnum.getErrorCode(), errorEnum.getMessage());
    }

    public APIException(ExceptionEnum errorEnum, String message) {
        this(errorEnum.getErrorCode(),message);
    }

    public Integer getErrorCode() {
        return errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
