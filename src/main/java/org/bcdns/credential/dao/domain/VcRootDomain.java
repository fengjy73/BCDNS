package org.bcdns.credential.dao.domain;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class VcRootDomain {
    private Integer id;
    private byte[] vcRoot;
}
