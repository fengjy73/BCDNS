package org.bcdns.credential.dao.domain;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Data
@NoArgsConstructor
public class ApiKeyDomain {
    private Integer id;
    private String apiKey;
    private String apiSecret;
    private String issuerPrivateKey;
    private byte[] issuerId;
    private Integer initTag;
}
