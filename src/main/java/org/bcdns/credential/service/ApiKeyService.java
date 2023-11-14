package org.bcdns.credential.service;


import org.bcdns.credential.dao.ApiKeyDAO;
import org.bcdns.credential.dao.domain.ApiKeyDomain;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
@Service
public class ApiKeyService {
    @Resource
    private ApiKeyDAO apiKeyDAO;

    public int insert(ApiKeyDomain apiKeyDomain){
        return apiKeyDAO.insert(apiKeyDomain);
    }

    public ApiKeyDomain getApiKeyByManagerId(byte[] managerId) {
        return apiKeyDAO.getApiKeyByManagerId(managerId);
    }

    public ApiKeyDomain getApiKeyDomain(Integer id) {
        return apiKeyDAO.getApiKeyDomain(id);
    }
}
