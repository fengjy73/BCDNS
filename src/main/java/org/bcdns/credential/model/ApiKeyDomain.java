package org.bcdns.credential.model;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class ApiKeyDomain {
    private Integer id;
    private String apiKey;
    private String apiSecret;
    private String issuerPrivateKey;
    private String issuerId;
    private Integer initTag;
}
