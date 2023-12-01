package org.bcdns.credential.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.bcdns.credential.model.ApiKeyDomain;
@Mapper
public interface ApiKeyMapper {
    public int insert(ApiKeyDomain apiKeyDomain);
    public ApiKeyDomain getApiKeyByManagerId(String issuerId);
    public ApiKeyDomain getApiKeyDomain(Integer id);
}
