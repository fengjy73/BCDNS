package org.bcdns.credential;

import org.bcdns.credential.dto.req.VcApplyDetailReqDto;
import org.bcdns.credential.dto.req.VcApplyListReqDto;
import org.bcdns.credential.dto.resp.VcApplyListRespDto;
import org.bcdns.credential.mapper.ApiKeyMapper;
import org.bcdns.credential.mapper.VcAuditMapper;
import org.bcdns.credential.mapper.VcRecordMapper;
import org.bcdns.credential.mapper.VcRootMapper;
import org.bcdns.credential.model.*;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.List;

@ActiveProfiles("dev")
@RunWith(SpringRunner.class)
@Sql(scripts = {"classpath:init.sql"}, executionPhase = Sql.ExecutionPhase.BEFORE_TEST_METHOD)
@Sql(scripts = {"classpath:drop.sql"}, executionPhase = Sql.ExecutionPhase.AFTER_TEST_METHOD)
@SpringBootTest(classes = CredentialApplication.class)
public class CredentialApplicationTests {

    @Autowired
    private ApiKeyMapper apiKeyMapper;

    @Autowired
    private VcAuditMapper vcAuditMapper;

    @Autowired
    private VcRecordMapper vcRecordMapper;

    @Autowired
    private VcRootMapper vcRootMapper;

    @Test
    public void testGetApiKeyDomain() {
        ApiKeyDomain apiKeyDomain = new ApiKeyDomain();
        apiKeyDomain.setApiKey("aaa");
        apiKeyDomain.setApiSecret("bbb");
        apiKeyDomain.setIssuerPrivateKey("ccc");
        apiKeyDomain.setIssuerId("ddd");
        apiKeyDomain.setInitTag(1);

        apiKeyMapper.insert(apiKeyDomain);
        ApiKeyDomain apiKeyDomain1 = apiKeyMapper.getApiKeyByManagerId("ddd");
        Assert.assertEquals("aaa", apiKeyDomain1.getApiKey());
        Assert.assertEquals("bbb", apiKeyDomain1.getApiSecret());
        Assert.assertEquals("ccc", apiKeyDomain1.getIssuerPrivateKey());
        Assert.assertEquals("ddd", apiKeyDomain1.getIssuerId());

        ApiKeyDomain apiKeyDomain2 = apiKeyMapper.getApiKeyDomain(1);
        Assert.assertEquals("aaa", apiKeyDomain2.getApiKey());
        Assert.assertEquals("bbb", apiKeyDomain2.getApiSecret());
        Assert.assertEquals("ccc", apiKeyDomain2.getIssuerPrivateKey());
        Assert.assertEquals("ddd", apiKeyDomain2.getIssuerId());
    }

    @Test
    public void testGetVcAuditDomain() {
        VcAuditDomain vcAuditDomain = new VcAuditDomain();
        vcAuditDomain.setApplyNo("aaa");
        vcAuditDomain.setVcId("bbb");
        Integer status = 1;
        vcAuditDomain.setStatus(status);
        byte[] auditId = {0, 1};
        vcAuditDomain.setAuditId(auditId);
        byte[] vcOwnerId = {0, 1};
        vcAuditDomain.setVcOwnerId(vcOwnerId);
        vcAuditDomain.setReason("test");
        vcAuditDomain.setCreateTime(100L);

        vcAuditMapper.insert(vcAuditDomain);
        VcAuditDomain vcAuditDomain1 = vcAuditMapper.getAuditDomain("aaa");
        Assert.assertEquals("aaa", vcAuditDomain1.getApplyNo());
        Assert.assertEquals("bbb", vcAuditDomain1.getVcId());
        Assert.assertEquals(status, vcAuditDomain1.getStatus());
        Assert.assertArrayEquals(auditId, vcAuditDomain1.getAuditId());
        Assert.assertArrayEquals(vcOwnerId, vcAuditDomain1.getVcOwnerId());
        Assert.assertEquals("test", vcAuditDomain1.getReason());
        Assert.assertEquals(100L, vcAuditDomain1.getCreateTime());
        Assert.assertEquals(0L, vcAuditDomain1.getUpdateTime());

        VcAuditDomain vcAuditDomain2 = vcAuditMapper.getVcIdByVcOwner(vcOwnerId);
        Assert.assertEquals("aaa", vcAuditDomain2.getApplyNo());
        Assert.assertEquals("bbb", vcAuditDomain2.getVcId());
        Assert.assertEquals(status, vcAuditDomain2.getStatus());
        Assert.assertArrayEquals(auditId, vcAuditDomain2.getAuditId());
        Assert.assertArrayEquals(vcOwnerId, vcAuditDomain2.getVcOwnerId());
        Assert.assertEquals("test", vcAuditDomain2.getReason());
        Assert.assertEquals(100L, vcAuditDomain2.getCreateTime());
        Assert.assertEquals(0L, vcAuditDomain2.getUpdateTime());
    }

    @Test
    public void testGetVcRecordDomain() {
        VcRecordDomain vcRecordDomain = new VcRecordDomain();
        vcRecordDomain.setApplyNo("aaa");
        byte[] content = {0, 1};
        vcRecordDomain.setContent(content);
        Integer credentialType = 1;
        vcRecordDomain.setCredentialType(credentialType);
        Integer status = 1;
        vcRecordDomain.setStatus(status);
        vcRecordDomain.setVcId("bbb");
        byte[] vcData = {0, 1};
        vcRecordDomain.setVcData(vcData);
        vcRecordDomain.setPublicKey("ccc");
        byte[] userId = {0, 1};
        vcRecordDomain.setUserId(userId);
        vcRecordDomain.setCreateTime(100L);
        Integer download = 1;
        vcRecordDomain.setIsDownload(download);

        vcRecordMapper.insert(vcRecordDomain);
        VcRecordDomain vcRecordDomain1 = vcRecordMapper.getVcRecord("aaa");
        Assert.assertEquals("aaa", vcRecordDomain1.getApplyNo());
        Assert.assertEquals(credentialType, vcRecordDomain1.getCredentialType());
        Assert.assertArrayEquals(content, vcRecordDomain1.getContent());
        Assert.assertEquals(status, vcRecordDomain1.getStatus());
        Assert.assertEquals("bbb", vcRecordDomain1.getVcId());
        Assert.assertArrayEquals(vcData, vcRecordDomain1.getVcData());
        Assert.assertEquals("ccc", vcRecordDomain1.getPublicKey());
        Assert.assertArrayEquals(userId, vcRecordDomain1.getUserId());
        Assert.assertEquals(100L, vcRecordDomain1.getCreateTime());
        Assert.assertEquals(0L, vcRecordDomain1.getUpdateTime());
        Assert.assertEquals(download, vcRecordDomain1.getIsDownload());

        VcRecordDomain vcRecordDomain2 = vcRecordMapper.getVcRecord4VcId("bbb");
        Assert.assertEquals("aaa", vcRecordDomain2.getApplyNo());
        Assert.assertEquals(credentialType, vcRecordDomain2.getCredentialType());
        Assert.assertArrayEquals(content, vcRecordDomain2.getContent());
        Assert.assertEquals(status, vcRecordDomain2.getStatus());
        Assert.assertEquals("bbb", vcRecordDomain2.getVcId());
        Assert.assertArrayEquals(vcData, vcRecordDomain2.getVcData());
        Assert.assertEquals("ccc", vcRecordDomain2.getPublicKey());
        Assert.assertArrayEquals(userId, vcRecordDomain2.getUserId());
        Assert.assertEquals(100L, vcRecordDomain2.getCreateTime());
        Assert.assertEquals(0L, vcRecordDomain2.getUpdateTime());
        Assert.assertEquals(download, vcRecordDomain2.getIsDownload());

        VcRecordDomain vcRecordDomain3 = vcRecordMapper.getVcRecord4UserId(userId);
        Assert.assertEquals("aaa", vcRecordDomain3.getApplyNo());
        Assert.assertEquals(credentialType, vcRecordDomain3.getCredentialType());
        Assert.assertArrayEquals(content, vcRecordDomain3.getContent());
        Assert.assertEquals(status, vcRecordDomain3.getStatus());
        Assert.assertEquals("bbb", vcRecordDomain3.getVcId());
        Assert.assertArrayEquals(vcData, vcRecordDomain3.getVcData());
        Assert.assertEquals("ccc", vcRecordDomain3.getPublicKey());
        Assert.assertArrayEquals(userId, vcRecordDomain3.getUserId());
        Assert.assertEquals(100L, vcRecordDomain3.getCreateTime());
        Assert.assertEquals(0L, vcRecordDomain3.getUpdateTime());
        Assert.assertEquals(download, vcRecordDomain3.getIsDownload());

        VcApplyListReqDto vcApplyListReqDto = new VcApplyListReqDto();
        Integer[] setStatus = {1};
        vcApplyListReqDto.setStatus(setStatus);
        List<VcRecordListDomain> vcRecordListDomains = vcRecordMapper.queryList(vcApplyListReqDto);
        Assert.assertEquals("aaa", vcRecordListDomains.get(0).getApplyNo());
        Assert.assertEquals("bbb", vcRecordListDomains.get(0).getCredentialId());
        Assert.assertEquals(status, vcRecordListDomains.get(0).getStatus());
        Assert.assertArrayEquals(userId, vcRecordListDomains.get(0).getUserId());
        Assert.assertEquals(100L, vcRecordListDomains.get(0).getCreateTime());
        Assert.assertEquals(credentialType, vcRecordListDomains.get(0).getCredentialType());
        Assert.assertEquals(download, vcRecordListDomains.get(0).getIsDownload());

        Assert.assertEquals(1, vcRecordMapper.queryListCount(vcApplyListReqDto));

        VcApplyDetailReqDto vcApplyDetailReqDto1 = new VcApplyDetailReqDto();
        vcApplyDetailReqDto1.setApplyNo("aaa");
        VcRecordDomain vcRecordDomain4 = vcRecordMapper.queryDetail(vcApplyDetailReqDto1);
        Assert.assertEquals("aaa", vcRecordDomain4.getApplyNo());
        Assert.assertEquals(credentialType, vcRecordDomain4.getCredentialType());
        Assert.assertArrayEquals(content, vcRecordDomain4.getContent());
        Assert.assertEquals(status, vcRecordDomain4.getStatus());
        Assert.assertEquals("bbb", vcRecordDomain4.getVcId());
        Assert.assertArrayEquals(vcData, vcRecordDomain4.getVcData());
        Assert.assertEquals("ccc", vcRecordDomain4.getPublicKey());
        Assert.assertArrayEquals(userId, vcRecordDomain4.getUserId());
        Assert.assertEquals(100L, vcRecordDomain4.getCreateTime());
        Assert.assertEquals(0L, vcRecordDomain4.getUpdateTime());
        Assert.assertEquals(download, vcRecordDomain4.getIsDownload());

        VcApplyDetailReqDto vcApplyDetailReqDto2 = new VcApplyDetailReqDto();
        vcApplyDetailReqDto2.setCredentialId("bbb");
        VcRecordDomain vcRecordDomain5 = vcRecordMapper.queryDetail(vcApplyDetailReqDto2);
        Assert.assertEquals("aaa", vcRecordDomain5.getApplyNo());
        Assert.assertEquals(credentialType, vcRecordDomain5.getCredentialType());
        Assert.assertArrayEquals(content, vcRecordDomain5.getContent());
        Assert.assertEquals(status, vcRecordDomain5.getStatus());
        Assert.assertEquals("bbb", vcRecordDomain5.getVcId());
        Assert.assertArrayEquals(vcData, vcRecordDomain5.getVcData());
        Assert.assertEquals("ccc", vcRecordDomain5.getPublicKey());
        Assert.assertArrayEquals(userId, vcRecordDomain5.getUserId());
        Assert.assertEquals(100L, vcRecordDomain5.getCreateTime());
        Assert.assertEquals(0L, vcRecordDomain5.getUpdateTime());
        Assert.assertEquals(download, vcRecordDomain5.getIsDownload());

        vcRecordDomain.setVcId("123");
        byte[] newVcData = {1,2,3,4};
        vcRecordDomain.setVcData(newVcData);
        vcRecordDomain.setUpdateTime(300L);
        vcRecordMapper.updateAuditPassStatus(vcRecordDomain);
        VcRecordDomain vcRecordDomain6 = vcRecordMapper.getVcRecord("aaa");
        Assert.assertEquals("123", vcRecordDomain6.getVcId());
        Assert.assertArrayEquals(newVcData, vcRecordDomain6.getVcData());
        Assert.assertEquals(300L, vcRecordDomain6.getUpdateTime());

        Integer newDownload = 0;
        vcRecordDomain.setIsDownload(newDownload);
        vcRecordMapper.updateIsDownloadByVcId(vcRecordDomain);
        VcRecordDomain vcRecordDomain7 = vcRecordMapper.getVcRecord("aaa");
        Assert.assertEquals(newDownload, vcRecordDomain7.getIsDownload());

        Integer newStatus = 4;
        vcRecordDomain.setStatus(newStatus);
        vcRecordMapper.updateRevokeStatus(vcRecordDomain);
        VcRecordDomain vcRecordDomain8 = vcRecordMapper.getVcRecord("aaa");
        Assert.assertEquals(newStatus, vcRecordDomain8.getStatus());
    }

    @Test
    public void testGetVcRootDomain() {
        VcRootDomain vcRootDomain = new VcRootDomain();
        Integer id = 1;
        vcRootDomain.setId(id);
        byte[] root = {1, 2, 3};
        vcRootDomain.setVcRoot(root);
        vcRootMapper.insert(vcRootDomain);

        VcRootDomain vcRootDomain1 = vcRootMapper.getVcRoot();
        Assert.assertEquals(id, vcRootDomain1.getId());
        Assert.assertArrayEquals(root, vcRootDomain1.getVcRoot());
    }
}
