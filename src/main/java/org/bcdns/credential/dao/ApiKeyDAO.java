package org.bcdns.credential.dao;

import net.paoding.rose.jade.annotation.DAO;
import net.paoding.rose.jade.annotation.SQL;
import org.bcdns.credential.dao.domain.ApiKeyDomain;
@DAO
public interface ApiKeyDAO {
    public static final String COLUMN = "id,api_key,api_secret,issuer_private_key,issuer_id,init_tag";

    @SQL("INSERT INTO api_key_record ($COLUMN) VALUES (:1.id,:1.apiKey,:1.apiSecret,:1.issuerPrivateKey,:1.issuerId,:1.initTag)")
    public int insert(ApiKeyDomain apiKeyDomain);
    @SQL("select $COLUMN from api_key_record where issuer_id = :1")
    public ApiKeyDomain getApiKeyByManagerId(byte[] issuerId);
    @SQL("select $COLUMN from api_key_record where id = :1")
    public ApiKeyDomain getApiKeyDomain(Integer id);
}
