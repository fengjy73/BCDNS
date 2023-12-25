package org.bcdns.credential.service;


import org.bcdns.credential.mapper.ApiKeyMapper;
import org.bcdns.credential.model.ApiKeyDomain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
@Service
public class ApiKeyService {

    @Autowired
    private ApiKeyMapper apiKeyMapper;

    public int insert(ApiKeyDomain apiKeyDomain){
        return apiKeyMapper.insert(apiKeyDomain);
    }

    public ApiKeyDomain getApiKeyByManagerId(String managerId) {
        return apiKeyMapper.getApiKeyByManagerId(managerId);
    }

    public ApiKeyDomain getApiKeyDomain(Integer id) {
        return apiKeyMapper.getApiKeyDomain(id);
    }
}
