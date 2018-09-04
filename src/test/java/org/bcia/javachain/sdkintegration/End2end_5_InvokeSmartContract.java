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

import org.bcia.javachain.common.exception.JavaChainException;
import org.bcia.javachain.sdk.*;
import org.bcia.javachain.sdk.TransactionRequest.Type;
import org.bcia.javachain.sdk.common.log.JavaChainLog;
import org.bcia.javachain.sdk.common.log.JavaChainLogFactory;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.helper.MspStore;
import org.bcia.javachain.sdk.security.csp.intfs.IKey;
import org.bcia.javachain.sdk.security.gm.CertificateUtils;
import org.bcia.javachain.sdk.testutils.TestConfig;
import org.bcia.javachain_ca.sdk.RegistrationRequest;
import org.junit.Test;

import java.io.File;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.fail;

/**
 * 测试调用智能合约的脚本
 * 此时脚本来自于End2endIT
 * 1.将ＧＯ语言部分去掉
 * 2.将路径做了改动
 * 3.将群组２去掉
 * 4.安装julongchain-sc-java智能合约
 * 5.将protos全面改为julongchain包
 * @author wangzhe
 */
public class End2end_5_InvokeSmartContract {

	private static JavaChainLog log = JavaChainLogFactory.getLog(End2end_5_InvokeSmartContract.class);
	
    private static final TestConfig testConfig = TestConfig.getConfig();
    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TESTUSER_1_NAME = "user1";
    private static final String TEST_FIXTURES_PATH = "src/test/fixture";

    private static final String FOO_CHANNEL_NAME = "myGroup";

    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    private static final String EXPECTED_EVENT_NAME = "event";
    private static final Map<String, String> TX_EXPECTED;

    static {
        TX_EXPECTED = new HashMap<>();
        TX_EXPECTED.put("readset1", "Missing readset for channel bar block 1");
        TX_EXPECTED.put("writeset1", "Missing writeset for channel bar block 1");
    }

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

    /**
     * 注册和嬁计用户存入samplestore.
     *
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

    //########################################################################################################################
    //
    //                  調用ＳＣ
    //
    //########################################################################################################################
    public static void invokeSC(SmartContractID smartContractID, String groupName, HFClient client, SampleOrg sampleOrg) throws Exception {

        //通過ｇｒｏｕｐＮａｍｅ得到ｇｒｏｕｐ對象
        Group newGroup = Group.createNewInstance(groupName, client);
        String peerName = sampleOrg.getNodeNames().toArray(new String[0])[0];
        String peerLocation = sampleOrg.getNodeLocation(peerName);
        boolean doNodeEventing = true;

        Properties peerProperties = testConfig.getNodeProperties(peerName); //test properties for peer.. if any.
        if (peerProperties == null) {
            peerProperties = new Properties();
        }

        Node peer = client.newNode(peerName, peerLocation, peerProperties);
        newGroup.addNode(peer);

        List<Consenter> orderers = loadConsenters(client, sampleOrg);
        for ( Consenter consenter : orderers ) {
            newGroup.addConsenter(consenter);
        }

        newGroup.initialize();

        client.setUserContext(sampleOrg.getUser(TESTUSER_1_NAME));
        Collection<ProposalResponse> successful = new LinkedList<>();
        Collection<ProposalResponse> failed = new LinkedList<>();
        ///////////////
        /// Send transaction proposal to all peers
        TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
        transactionProposalRequest.setSmartContractID(smartContractID);
        transactionProposalRequest.setSmartContractLanguage(Type.JAVA);
        //transactionProposalRequest.setFcn("invoke");
        transactionProposalRequest.setFcn("move");
        transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
        transactionProposalRequest.setArgs("a", "b", "100");

        Map<String, byte[]> tm2 = new HashMap<>();
        tm2.put("HyperLedgerFabric", "TransactionProposalRequest:JavaSDK".getBytes(UTF_8)); //Just some extra junk in transient map
        tm2.put("method", "TransactionProposalRequest".getBytes(UTF_8)); // ditto
        tm2.put("result", ":)".getBytes(UTF_8));  // This should be returned see chaincode why.
        tm2.put(EXPECTED_EVENT_NAME, EXPECTED_EVENT_DATA);  //This should trigger an event see chaincode why.

        transactionProposalRequest.setTransientMap(tm2);

        info("sending transactionProposal to all peers with arguments: move(a,b,100)");

        Collection<ProposalResponse> transactionPropResp = newGroup.sendTransactionProposal(transactionProposalRequest, newGroup.getNodes());
        for (ProposalResponse response : transactionPropResp) {
            log.info("______status:_______"+ response.getStatus());
            //if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
            if (response.getStatus() == ProposalResponse.Status.SUCCESS
                    || response.getStatus() == ProposalResponse.Status.UNDEFINED ) {//TODO 200和０暂时都算返回成功，等julongchain返回码统一
                info("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getNode().getName());
                successful.add(response);
            } else {
                failed.add(response);
            }
        }

        // Check that all the proposals are consistent with each other. We should have only one set
        // where all the proposals above are consistent. Note the when sending to Consenter this is done automatically.
        //  Shown here as an example that applications can invoke and select.
        // See org.bcia.javachain.sdk.proposal.consistency_validation config property.
        /*
        //TODO 这个校验暂时不加算返回成功，等julongchain返回码统一
        Collection<Set<ProposalResponse>> proposalConsistencySets = SDKUtils.getProposalConsistencySets(transactionPropResp);
        if (proposalConsistencySets.size() != 1) {
            fail(format("Expected only one set of consistent proposal responses but got %d", proposalConsistencySets.size()));
        }
        */

        info("Received %d transaction proposal responses. Successful+verified: %d . Failed: %d",
                transactionPropResp.size(), successful.size(), failed.size());
        if (failed.size() > 0) {
            ProposalResponse firstTransactionProposalResponse = failed.iterator().next();
            fail("Not enough endorsers for invoke(move a,b,100):" + failed.size() + " endorser error: " +
                    firstTransactionProposalResponse.getMessage() +
                    ". Was verified: " + firstTransactionProposalResponse.isVerified());
        }
        info("Successfully received transaction proposal responses.");
        /*
        //TODO 这个校验暂时不加算返回成功，等julongchain返回码统一
        ProposalResponse resp = successful.iterator().next();
        byte[] x = resp.getSmartContractActionResponsePayload(); // This is the data returned by the chaincode.
        String resultAsString = null;
        if (x != null) {
            resultAsString = new String(x, "UTF-8");
        }
        assertEquals(":)", resultAsString);

        assertEquals(200, resp.getSmartContractActionResponseStatus()); //SmartContract's status.

        TxReadWriteSetInfo readWriteSetInfo = resp.getSmartContractActionResponseReadWriteSetInfo();
        //See blockwalker below how to transverse this
        assertNotNull(readWriteSetInfo);
        assertTrue(readWriteSetInfo.getNsRwsetCount() > 0);

        SmartContractID cid = resp.getSmartContractID();
        assertNotNull(cid);
        final String path = cid.getPath();

        */
        ////////////////////////////
        // Send Transaction Transaction to orderer
        info("Sending chaincode transaction(move a,b,100) to orderer.");
        newGroup.sendTransaction(successful).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);

        info("invoke success!");
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

    @Test
    public void testInvokeSmartContact() throws Exception {
        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        if (sampleStoreFile.exists()) { //For testing start fresh
            sampleStoreFile.delete();
        }
        SampleStore sampleStore = new SampleStore(sampleStoreFile);
        Collection<SampleOrg> sampleOrgs = testConfig.getIntegrationTestsSampleOrgs();
        SampleOrg sampleOrg = sampleOrgs.toArray(new SampleOrg[0])[0];
        HFClient client = HFClient.createNewInstance();

        initUser(sampleOrgs, sampleStore);
        log.info("user has inited................");
        client.setUserContext(sampleOrg.getNodeAdmin());

        SmartContractID.Builder chaincodeIDBuilder = SmartContractID.newBuilder().setName("mycc").setVersion("1.0");
        final SmartContractID chaincodeID = chaincodeIDBuilder.build();

        initUser(sampleOrgs, sampleStore);
        log.info("user has inited................");

        invokeSC(chaincodeID, "myGroup", client, sampleOrg);
        log.info("group has invoked................");
    }

}
