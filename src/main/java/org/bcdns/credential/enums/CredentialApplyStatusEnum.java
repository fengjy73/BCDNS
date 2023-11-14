package org.bcdns.credential.enums;

public enum CredentialApplyStatusEnum {
	T1(1, "待审核"),
	T2(2, "审核通过"),
	T3(3, "审核不通过"),
	T4(4, "吊销"),
	T5(5, "不可信"),
	;
	private Integer code;
	private String name;

	private CredentialApplyStatusEnum(Integer code, String name) {
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
		for(CredentialApplyStatusEnum credentialStatus: CredentialApplyStatusEnum.values()){
			if(code.equals(credentialStatus.getCode())){
				return credentialStatus.getName();
			}
		}
		return  null;
	}

	
}
