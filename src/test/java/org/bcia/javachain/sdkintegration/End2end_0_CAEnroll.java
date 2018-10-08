/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.bcia.javachain.sdkintegration;

import org.bcia.javachain.sdk.Enrollment;
import org.bcia.javachain.sdk.User;
import org.bcia.javachain.sdk.testutils.TestConfig;
import org.bcia.javachain_ca.sdk.EnrollmentRequest;
import org.bcia.javachain_ca.sdk.HFCAClient;
import org.bcia.javachain_ca.sdk.exception.EnrollmentException;
import org.bcia.javachain_ca.sdk.exception.InvalidArgumentException;
import org.bcia.javachain_ca.sdk.exception.RevocationException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;

import static org.bcia.javachain.sdk.testutils.TestUtils.resetConfig;

/**
 * CA服务器接口测试类
 * 主要实现了获取证书和注销证书的测试方法
 */
public class End2end_0_CAEnroll {

    private HFCAClient client;

    private SampleStore sampleStore;

    private static TestConfig testConfig = TestConfig.getConfig();

    private static final String TEST_WITH_INTEGRATION_ORG = "peerOrg1";

    private static final String TEST_ADMIN_NAME = "admin";

    private static final String TEST_ADMIN_ORG = "org1";

    private SampleUser admin;

    private static final String TEST_ADMIN_PW = "adminpw";

    @BeforeClass
    public static void init() throws Exception {
        resetConfig();
    }

    @Before
    public void setup() throws Exception {

        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        if (sampleStoreFile.exists()) { // For testing start fresh
            sampleStoreFile.delete();
        }
        sampleStore = new SampleStore(sampleStoreFile);
        sampleStoreFile.deleteOnExit();

        client = HFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
//        client.setCryptoSuite(crypto);

        // SampleUser can be any implementation that implements org.bcia.javachain.sdk.User Interface
        admin = sampleStore.getMember(TEST_ADMIN_NAME, TEST_ADMIN_ORG);
        if (!admin.isEnrolled()) { // Preregistered admin only needs to be enrolled with Fabric CA.
            admin.setEnrollment(client.enroll(admin.getName(), TEST_ADMIN_PW));
        }

    }


    @Test
    public void testEnroll() throws EnrollmentException, InvalidArgumentException {
        String user = "ft00000008"; //用户名，用户唯一标识，不能为空
        String secret = "1";
        EnrollmentRequest rq = new EnrollmentRequest();
        rq.setPassword("123456");//用户密码，不能为空
        rq.setCN("ft00000008");//通用名，不能为空
        rq.setO("SZCAFT000008");//组织机构名称
        rq.setC("CN"); //ISO 3166国家代码
        rq.setL("广州市");//城市
        rq.setS("广东省");//省份
        rq.setOU("技术中心");//部门
        rq.setProcessId("14");//实体证书流程ID，不能为空
        rq.setCertType("1");//获取证书类型 1 : Certificate 公钥证书  2 : PKCS12 P12证书  3 : JKS  JKS证书
        rq.setReqType("1"); //请求类型：  1 : 证书申请    2 : 证书更新
        rq.setKeyType("2");//密钥类型，certType等于2或3时有效。    当无此参数时，默认是RSA2048              当keyType=2时，为SM2
        rq.setCsr("CN=ft00000008"); //证书请求CSR，当certType等于1时必填
        client.enroll(user,secret,rq);
    }

    @Test
    public void testRevoke() throws InvalidArgumentException, RevocationException {
        String userName = "tf00000001";
        String reqType = "2";////请求类型  1：撤销用户  2：撤销单个证书
        String revokeReason ="5"; //撤销原因: 0 : 没有指定 1 : 密钥损坏   2 : CA损坏  3 : 从属关系改变   4 : 证书替换  5 : 停止使用   6 : 证书挂起  8 : 从CRL中删除  9 : 撤销权限   10 : AA泄密
        String serialNo = ""; //当reqType等于2时填,不传的时候后面根据证书转换获取
        String revokeCertFile = "/home/tf00000001.cer";

        SampleStore keyValStore = new SampleStore(new File(revokeCertFile));
        SampleUser spUser = new SampleUser(userName,"0",keyValStore);

        client.revoke(spUser,reqType,revokeReason,serialNo,revokeCertFile);

    }
}
