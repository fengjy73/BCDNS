package org.bcdns.credential.enums;

public enum CredentialStatusEnum {
	T0(0, "未做可信认证"),
	T1(1, "可信"),
	T2(2, "可信认证已过期"),
	T3(3, "可信认证被吊销"),
	;
	private Integer code;
	private String name;

	private CredentialStatusEnum(Integer code, String name) {
		this.code = code;
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public Integer getCode() {
		return code;
	}


	public static String getValueByCode(Integer code){
		for(CredentialStatusEnum credentialStatus:CredentialStatusEnum.values()){
			if(code.equals(credentialStatus.getCode())){
				return credentialStatus.getName();
			}
		}
		return  null;
	}

	
}
