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

import org.apache.commons.codec.binary.Hex;
import org.bcia.javachain.sdk.*;
import org.bcia.javachain.sdk.Node.NodeRole;
import org.bcia.javachain.sdk.TransactionRequest.Type;
import org.bcia.javachain.sdk.exception.*;
import org.bcia.javachain.sdk.helper.MspStore;
import org.bcia.javachain.sdk.security.CryptoSuite;
import org.bcia.javachain.sdk.security.gm.CertificateUtils;
import org.bcia.javachain.sdk.testutils.TestConfig;
import org.bcia.javachain_ca.sdk.RegistrationRequest;
import org.bcia.javachain.common.exception.JavaChainException;
import org.bcia.javachain.common.localmsp.ILocalSigner;
import org.bcia.javachain.common.localmsp.impl.LocalSigner;
import org.bcia.javachain.sdk.common.log.JavaChainLog;
import org.bcia.javachain.sdk.common.log.JavaChainLogFactory;
import org.bcia.javachain.sdk.security.csp.intfs.IKey;
import org.bcia.javachain.sdk.security.msp.IIdentityDeserializer;
import org.bcia.javachain.sdk.security.msp.ISigningIdentity;
import org.bcia.javachain.sdk.security.msp.mgmt.GlobalMspManagement;
import org.bcia.julongchain.protos.ledger.rwset.kvrwset.KvRwset;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.bcia.javachain.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;
import static org.bcia.javachain.sdk.Group.NOfEvents.createNofEvents;
import static org.bcia.javachain.sdk.Group.NodeOptions.createNodeOptions;
import static org.bcia.javachain.sdk.Group.TransactionOptions.createTransactionOptions;
import static org.junit.Assert.*;

/**
 * Test end to end scenario
 * 此时脚本来自于End2endIT
 * 1.将ＧＯ语言部分去掉
 * 2.将路径做了改动
 * 3.将群组２去掉
 * 4.安装julongchain-sc-java智能合约
 * 5.将protos全面改为julongchain包
 * @author wangzhe version 3.0
 */
public class End2end_1_CreateGroup {

	private static JavaChainLog log = JavaChainLogFactory.getLog(End2end_1_CreateGroup.class);
	
    private static final TestConfig testConfig = TestConfig.getConfig();
    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TESTUSER_1_NAME = "user1";
    private static final String TEST_FIXTURES_PATH = "src/test/fixture";

    private static final String FOO_CHANNEL_NAME = "myGroup";

    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    private static final String EXPECTED_EVENT_NAME = "event";
    private static final Map<String, String> TX_EXPECTED;

    String testName = "End2endIT";

    String SMART_CONTRACT_FILEPATH = "";//直接拼接fixture和name
    String SMART_CONTRACT_NAME = "julongchain-sc-java";
    String SMART_CONTRACT_VERSION = "1";
    Type SMART_CONTRACT_LANG = Type.JAVA;

    static {
        TX_EXPECTED = new HashMap<>();
        TX_EXPECTED.put("readset1", "Missing readset for channel bar block 1");
        TX_EXPECTED.put("writeset1", "Missing writeset for channel bar block 1");
    }

    private final TestConfigHelper configHelper = new TestConfigHelper();
    String testTxID = null;  // save the CC invoke TxID and use in queries
    SampleStore sampleStore = null;
//    private Collection<SampleOrg> testSampleOrgs;

    static void info(String format, Object... args) {
//        System.err.flush();
//        System.info.flush();
        log.info(format(format, args));
//        System.err.flush();
//        System.info.flush();
    }
    //CHECKSTYLE.ON: Method length is 320 lines (max allowed is 150).

    static String printableString(final String string) {
        int maxLogStringLength = 64;
        if (string == null || string.length() == 0) {
            return string;
        }

        String ret = string.replaceAll("[^\\p{Print}]", "?");

        ret = ret.substring(0, Math.min(ret.length(), maxLogStringLength)) + (ret.length() > maxLogStringLength ? "..." : "");

        return ret;

    }

    @Before
    public void checkConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, MalformedURLException, org.bcia.javachain_ca.sdk.exception.InvalidArgumentException {
        info("\n\n\nRUNNING: %s.\n", testName);

        configHelper.customizeConfig();

        //testSampleOrgs = testConfig.getIntegrationTestsSampleOrgs();

    }

    Map<String, Properties> clientTLSProperties = new HashMap<>();

    /**
     * 注册和嬁计用户存入samplestore.
     * 初始化用户
     * @param sampleStore
     * @throws Exception
     */
    public static void initUser(Collection<SampleOrg> sampleOrgs, SampleStore sampleStore) throws Exception {
        ////////////////////////////
        //Set up USERS

        //SampleUser can be any implementation that implements org.bcia.javachain.sdk.User Interface

        ////////////////////////////
        // get users for all orgs

        for (SampleOrg sampleOrg : sampleOrgs) {

            //HFCAClient ca = sampleOrg.getCAClient();

            final String orgName = sampleOrg.getName();
            final String mspid = sampleOrg.getMSPID();

            //找到指定机构的管理员
            SampleUser admin = sampleStore.getMember(TEST_ADMIN_NAME, orgName);
            if (!admin.isEnrolled()) {  //Preregistered admin only needs to be enrolled with Fabric caClient.
                //############################################
                //
                //      第一步該管理員的ｅｎｒｏｌｌｍｅｎｔ
                //
                //############################################
                admin.setEnrollment(new Enrollment() {

                    @Override
                    public IKey getKey() {

                        try {
                            return CertificateUtils.bytesToPrivateKey(MspStore.getInstance().getClientKeys().get(0));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        return null;
                    }

                    @Override
                    public byte[] getCert() {

                        try {
                            return MspStore.getInstance().getAdminCerts().get(0);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        return null;
                    }
                });
                admin.setMspId(mspid);
            }

            sampleOrg.setAdmin(admin); // The admin of this org --
            //找到指定机构的用户
            SampleUser user = sampleStore.getMember(TESTUSER_1_NAME, sampleOrg.getName());
            if (!user.isRegistered()) {  // users need to be registered AND enrolled
                RegistrationRequest rr = new RegistrationRequest(user.getName(), "org1.department1");
                //user.setEnrollmentSecret(ca.register(rr, admin));
            }
            if (!user.isEnrolled()) {
                user.setEnrollment(new Enrollment() {

                    @Override
                    public IKey getKey() {
                        try {
                            return CertificateUtils.bytesToPrivateKey(MspStore.getInstance().getClientKeys().get(0));
                        } catch (JavaChainException e) {
                            e.printStackTrace();
                        }
                        return null;
                    }

                    @Override
                    public byte[] getCert() {
                        try {
                            return MspStore.getInstance().getClientCerts().get(0);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        return null;
                    }
                });
                user.setMspId(mspid);
            }
            sampleOrg.addUser(user); //Remember user belongs to this Org

            final String sampleOrgName = sampleOrg.getName();
            final String sampleOrgDomainName = sampleOrg.getDomainName();

            SampleUser peerOrgAdmin = sampleStore.getMember(sampleOrgName + "Admin", sampleOrgName);
            sampleOrg.setNodeAdmin(peerOrgAdmin); //A special user that can create channels, join peers and install chaincode

        }

    }

    //################################################################################################################################
    //
    //                          創建羣組180815
    //
    //################################################################################################################################
    public static Group createGroup(String groupName, HFClient client, SampleOrg sampleOrg) throws InvalidArgumentException, TransactionException {

        boolean doNodeEventing = !testConfig.isRunningAgainstFabric10() && FOO_CHANNEL_NAME.equals(groupName);
        //Only peer Admin org

        List<Consenter> orderers = loadConsenters(client, sampleOrg);

        //GroupConfiguration channelConfiguration = new GroupConfiguration(new File("/home/bcia/javachain-sdk-ftsafe/src/test/fixture/sdkintegration/e2e-2Orgs/v1.1/myGroup.tx"));
        GroupConfiguration channelConfiguration = null;
        //创建只有一个签名者的群组，该签名者是此orgs node admin。如果群组创建策略需要更多签名，则还需要添加它们。
        Group newGroup = client.newGroup(groupName, orderers.get(0), channelConfiguration, client.getGroupConfigurationSignature(channelConfiguration, sampleOrg.getNodeAdmin()));
        info("Created group %s", groupName);

        return newGroup;
    }

    public static List<Consenter> loadConsenters(HFClient client, SampleOrg sampleOrg) throws InvalidArgumentException {
        List<Consenter> orderers = new ArrayList<>();

        //循环consenter名称设置属性
        for (String orderName : sampleOrg.getConsenterNames()) {

            Properties ordererProperties = testConfig.getConsenterProperties(orderName);
            ordererProperties.put("grpc.NettyGroupBuilderOption.keepAliveTime", new Object[] {5L, TimeUnit.MINUTES});
            ordererProperties.put("grpc.NettyGroupBuilderOption.keepAliveTimeout", new Object[] {60L, TimeUnit.SECONDS});
            ordererProperties.put("grpc.NettyGroupBuilderOption.keepAliveWithoutCalls", new Object[] {true});
            orderers.add(client.newConsenter(orderName, sampleOrg.getConsenterLocation(orderName), ordererProperties));
        }
        return orderers;
    }

    public static void main(String[] args) throws Exception {
        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        if (sampleStoreFile.exists()) { //For testing start fresh
            sampleStoreFile.delete();
        }
        SampleStore sampleStore = new SampleStore(sampleStoreFile);
        Collection<SampleOrg> sampleOrgs = testConfig.getIntegrationTestsSampleOrgs();
        SampleOrg sampleOrg = sampleOrgs.toArray(new SampleOrg[0])[0];
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        initUser(sampleOrgs, sampleStore);
        client.setUserContext(sampleOrg.getNodeAdmin());
        log.info("user has inited................");

        Group newGroup = createGroup("myGroup", client, sampleOrg);
        log.info("group has created................");


        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

}
