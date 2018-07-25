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

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.bcia.javachain.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;
import static org.bcia.javachain.sdk.Group.NOfEvents.createNofEvents;
import static org.bcia.javachain.sdk.Group.NodeOptions.createNodeOptions;
import static org.bcia.javachain.sdk.Group.TransactionOptions.createTransactionOptions;
import static org.bcia.javachain.sdk.testutils.TestUtils.resetConfig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Hex;
import org.bcia.javachain.sdk.BlockEvent;
import org.bcia.javachain.sdk.BlockInfo;
import org.bcia.javachain.sdk.BlockchainInfo;
import org.bcia.javachain.sdk.Consenter;
import org.bcia.javachain.sdk.Enrollment;
import org.bcia.javachain.sdk.EventHub;
import org.bcia.javachain.sdk.Group;
import org.bcia.javachain.sdk.GroupConfiguration;
import org.bcia.javachain.sdk.HFClient;
import org.bcia.javachain.sdk.InstallProposalRequest;
import org.bcia.javachain.sdk.InstantiateProposalRequest;
import org.bcia.javachain.sdk.Node;
import org.bcia.javachain.sdk.Node.NodeRole;
import org.bcia.javachain.sdk.ProposalResponse;
import org.bcia.javachain.sdk.QueryBySmartContractRequest;
import org.bcia.javachain.sdk.SDKUtils;
import org.bcia.javachain.sdk.SmartContractEndorsementPolicy;
import org.bcia.javachain.sdk.SmartContractEvent;
import org.bcia.javachain.sdk.SmartContractID;
import org.bcia.javachain.sdk.TestConfigHelper;
import org.bcia.javachain.sdk.TransactionInfo;
import org.bcia.javachain.sdk.TransactionProposalRequest;
import org.bcia.javachain.sdk.TransactionRequest.Type;
import org.bcia.javachain.sdk.TxReadWriteSetInfo;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.bcia.javachain.sdk.exception.ProposalException;
import org.bcia.javachain.sdk.exception.TransactionEventException;
import org.bcia.javachain.sdk.security.CryptoSuite;
import org.bcia.javachain.sdk.testutils.TestConfig;
import org.bcia.javachain_ca.sdk.EnrollmentRequest;
import org.bcia.javachain_ca.sdk.HFCAClient;
import org.bcia.javachain_ca.sdk.HFCAInfo;
import org.bcia.javachain_ca.sdk.RegistrationRequest;
import org.bcia.julongchain.common.log.JavaChainLog;
import org.bcia.julongchain.common.log.JavaChainLogFactory;
import org.bcia.julongchain.protos.ledger.rwset.kvrwset.KvRwset;
import org.bouncycastle.openssl.PEMWriter;
import org.junit.Before;
import org.junit.Test;

/**
 * Test end to end scenario
 * 此时脚本来自于End2endIT
 * 1.将ＧＯ语言部分去掉
 * 2.将路径做了改动
 * 3.将群组２去掉
 * 4.安装julongchain-sc-java智能合约
 * 5.将protos全面改为julongchain包
 * @author wangzhe version 1.0
 */
public class End2JulongchainIT {

	private static JavaChainLog log = JavaChainLogFactory.getLog(End2JulongchainIT.class);
	
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
    private Collection<SampleOrg> testSampleOrgs;

    static void out(String format, Object... args) {
//        System.err.flush();
//        System.out.flush();
        log.info(format(format, args));
//        System.err.flush();
//        System.out.flush();
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
        out("\n\n\nRUNNING: %s.\n", testName);
        //   configHelper.clearConfig();
        //   assertEquals(256, Config.getConfig().getSecurityLevel());
        resetConfig();
        configHelper.customizeConfig();

        testSampleOrgs = testConfig.getIntegrationTestsSampleOrgs();
        //Set up hfca for each sample org

        for (SampleOrg sampleOrg : testSampleOrgs) {
            String caName = sampleOrg.getCAName(); //Try one of each name and no name.
            if (caName != null && !caName.isEmpty()) {
                sampleOrg.setCAClient(HFCAClient.createNewInstance(caName, sampleOrg.getCALocation(), sampleOrg.getCAProperties()));
            } else {
                sampleOrg.setCAClient(HFCAClient.createNewInstance(sampleOrg.getCALocation(), sampleOrg.getCAProperties()));
            }
        }
    }

    Map<String, Properties> clientTLSProperties = new HashMap<>();

    File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");

    @Test
    public void setup() throws Exception {
        //Persistence is not part of SDK. Sample file store is for demonstration purposes only!
        //   MUST be replaced with more robust application implementation  (Database, LDAP)

        if (sampleStoreFile.exists()) { //For testing start fresh
            sampleStoreFile.delete();
        }
        sampleStore = new SampleStore(sampleStoreFile);

        enrollUsersSetup(sampleStore); //This enrolls users with fabric ca and setups sample store to get users later.
        runFabricTest(sampleStore); //Runs Fabric tests with constructing channels, joining peers, exercising chaincode

    }

    public void runFabricTest(final SampleStore sampleStore) throws Exception {

        ////////////////////////////
        // 初始化客户端

        //Create instance of client.
        HFClient client = HFClient.createNewInstance();

        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        ////////////////////////////
        //取出机构1构建群组
        SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg1");
        Group fooGroup = constructGroup(FOO_CHANNEL_NAME, client, sampleOrg);
        //保存群组
        sampleStore.saveGroup(fooGroup);
        //运行群组
        runGroup(client, fooGroup, true, sampleOrg, 0);
        assertFalse(fooGroup.isShutdown());
        fooGroup.shutdown(true); // Force foo channel to shutdown clean up resources.
        assertTrue(fooGroup.isShutdown());
        assertNull(client.getGroup(FOO_CHANNEL_NAME));
        out("\n");
//-----------------群组２暂时注释
//        sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg2");
//        Group barGroup = constructGroup(BAR_CHANNEL_NAME, client, sampleOrg);
//        assertTrue(barGroup.isInitialized());
//        sampleStore.saveGroup(barGroup);
//        assertFalse(barGroup.isShutdown());
//        runGroup(client, barGroup, true, sampleOrg, 100); //run a newly constructed bar channel with different b value!
//        out("\nTraverse the blocks for chain %s ", barGroup.getName());
//        blockWalker(client, barGroup);
//        assertFalse(barGroup.isShutdown());
//        assertTrue(barGroup.isInitialized());
//-----------------群组２暂时注释
        out("That's all folks!");
    }

    /**
     * 注册和嬁计用户存入samplestore.
     *
     * @param sampleStore
     * @throws Exception
     */
    public void enrollUsersSetup(SampleStore sampleStore) throws Exception {
        ////////////////////////////
        //Set up USERS

        //SampleUser can be any implementation that implements org.bcia.javachain.sdk.User Interface

        ////////////////////////////
        // get users for all orgs

        for (SampleOrg sampleOrg : testSampleOrgs) {

            HFCAClient ca = sampleOrg.getCAClient();

            final String orgName = sampleOrg.getName();
            final String mspid = sampleOrg.getMSPID();
            ca.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            if (testConfig.isRunningFabricTLS()) {
                //This shows how to get a client TLS certificate from Fabric CA
                // we will use one client TLS certificate for orderer peers etc.
                final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
                enrollmentRequestTLS.addHost("localhost");
                enrollmentRequestTLS.setProfile("tls");
                final Enrollment enroll = ca.enroll("admin", "adminpw", enrollmentRequestTLS);
                //取的ＣＡ证书
                final String tlsCertPEM = enroll.getCert();
                //取的ＣＡ公私钥
                final String tlsKeyPEM = getPEMStringFromPrivateKey(enroll.getKey());
                final Properties tlsProperties = new Properties();
                tlsProperties.put("clientKeyBytes", tlsKeyPEM.getBytes(UTF_8));
                tlsProperties.put("clientCertBytes", tlsCertPEM.getBytes(UTF_8));
                //放类变量里,机构名做key，property做值
                clientTLSProperties.put(sampleOrg.getName(), tlsProperties);
                //为了接下来的测试，保存到 samplestore
                sampleStore.storeClientPEMTLCertificate(sampleOrg, tlsCertPEM);
                sampleStore.storeClientPEMTLSKey(sampleOrg, tlsKeyPEM);
            }

            HFCAInfo info = ca.info(); //just check if we connect at all.
            assertNotNull(info);
            String infoName = info.getCAName();
            if (infoName != null && !infoName.isEmpty()) {
                assertEquals(ca.getCAName(), infoName);
            }
            //找到指定机构的管理员
            SampleUser admin = sampleStore.getMember(TEST_ADMIN_NAME, orgName);
            if (!admin.isEnrolled()) {  //Preregistered admin only needs to be enrolled with Fabric caClient.
            	//TODO 管理员不用register?
                admin.setEnrollment(ca.enroll(admin.getName(), "adminpw"));
                admin.setMspId(mspid);
            }

            sampleOrg.setAdmin(admin); // The admin of this org --
            //找到指定机构的用户
            SampleUser user = sampleStore.getMember(TESTUSER_1_NAME, sampleOrg.getName());
            if (!user.isRegistered()) {  // users need to be registered AND enrolled
                RegistrationRequest rr = new RegistrationRequest(user.getName(), "org1.department1");
                user.setEnrollmentSecret(ca.register(rr, admin));
            }
            if (!user.isEnrolled()) {
                user.setEnrollment(ca.enroll(user.getName(), user.getEnrollmentSecret()));
                user.setMspId(mspid);
            }
            sampleOrg.addUser(user); //Remember user belongs to this Org

            final String sampleOrgName = sampleOrg.getName();
            final String sampleOrgDomainName = sampleOrg.getDomainName();

            //例如：src/test/fixture/sdkintegration/e2e-2Orgs/channel/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/
            //通过这些参数拼接证书地址
            SampleUser peerOrgAdmin = sampleStore.getMember(sampleOrgName + "Admin", sampleOrgName, sampleOrg.getMSPID(),
                    Util.findFileSk(Paths.get(testConfig.getTestGroupPath(), "crypto-config/peerOrganizations/", sampleOrgDomainName, format("/users/Admin@%s/msp/keystore", sampleOrgDomainName)).toFile()),
                    Paths.get(testConfig.getTestGroupPath(), "crypto-config/peerOrganizations/", sampleOrgDomainName, format("/users/Admin@%s/msp/signcerts/Admin@%s-cert.pem", sampleOrgDomainName, sampleOrgDomainName)).toFile());

            sampleOrg.setNodeAdmin(peerOrgAdmin); //A special user that can create channels, join peers and install chaincode

        }

    }

    static String getPEMStringFromPrivateKey(PrivateKey privateKey) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(pemStrWriter);

        pemWriter.writeObject(privateKey);

        pemWriter.close();

        return pemStrWriter.toString();
    }

    //CHECKSTYLE.OFF: Method length is 320 lines (max allowed is 150).
    void runGroup(HFClient client, Group channel, boolean installSmartContract, SampleOrg sampleOrg, int delta) {

        class SmartContractEventCapture { //A test class to capture chaincode events
            final String handle;
            final BlockEvent blockEvent;
            final SmartContractEvent chaincodeEvent;

            SmartContractEventCapture(String handle, BlockEvent blockEvent, SmartContractEvent chaincodeEvent) {
                this.handle = handle;
                this.blockEvent = blockEvent;
                this.chaincodeEvent = chaincodeEvent;
            }
        }
        Vector<SmartContractEventCapture> chaincodeEvents = new Vector<>(); // Test list to capture chaincode events.

        try {

            final String channelName = channel.getName();
            boolean isFooChain = FOO_CHANNEL_NAME.equals(channelName);
            out("Running channel %s", channelName);

            Collection<Consenter> orderers = channel.getConsenters();
            final SmartContractID chaincodeID;
            Collection<ProposalResponse> responses;
            Collection<ProposalResponse> successful = new LinkedList<>();
            Collection<ProposalResponse> failed = new LinkedList<>();

            // Register a chaincode event listener that will trigger for any chaincode id and only for EXPECTED_EVENT_NAME event.

            String chaincodeEventListenerHandle = channel.registerSmartContractEventListener(Pattern.compile(".*"),
                    Pattern.compile(Pattern.quote(EXPECTED_EVENT_NAME)),
                    (handle, blockEvent, chaincodeEvent) -> {

                        chaincodeEvents.add(new SmartContractEventCapture(handle, blockEvent, chaincodeEvent));

                        String es = blockEvent.getNode() != null ? blockEvent.getNode().getName() : blockEvent.getEventHub().getName();
                        out("RECEIVED SmartContract event with handle: %s, chaincode Id: %s, chaincode event name: %s, "
                                        + "transaction id: %s, event payload: \"%s\", from eventhub: %s",
                                handle, chaincodeEvent.getSmartContractId(),
                                chaincodeEvent.getEventName(),
                                chaincodeEvent.getTxId(),
                                new String(chaincodeEvent.getPayload()), es);

                    });

            //For non foo channel unregister event listener to test events are not called.
            if (!isFooChain) {
                channel.unregisterSmartContractEventListener(chaincodeEventListenerHandle);
                chaincodeEventListenerHandle = null;

            }
            //创建智能合约
            SmartContractID.Builder chaincodeIDBuilder = SmartContractID.newBuilder().setName(SMART_CONTRACT_NAME)
                    .setVersion(SMART_CONTRACT_VERSION);
//此处SMART_CONTRACT_PATH变量暂时去掉了，这个也随之注释掉了
//            if (null != SMART_CONTRACT_PATH) {
//                chaincodeIDBuilder.setPath(SMART_CONTRACT_PATH);
//            }
            chaincodeID = chaincodeIDBuilder.build();

            if (installSmartContract) {
                ////////////////////////////
                // Install Proposal Request
                //

                client.setUserContext(sampleOrg.getNodeAdmin());

                out("Creating install proposal");

                InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
                installProposalRequest.setSmartContractID(chaincodeID);

                if (isFooChain) {
                    // on foo chain install from directory.

                    ////For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
                    installProposalRequest.setSmartContractSourceLocation(Paths.get(TEST_FIXTURES_PATH, SMART_CONTRACT_FILEPATH).toFile());
                } else {
                    // On bar chain install from an input stream.

                    if (SMART_CONTRACT_LANG.equals(Type.GO_LANG)) {
//GO语言暂不支持
//                        installProposalRequest.setSmartContractInputStream(Util.generateTarGzInputStream(
//                                (Paths.get(TEST_FIXTURES_PATH, SMART_CONTRACT_FILEPATH, "src", SMART_CONTRACT_PATH).toFile()),
//                                Paths.get("src", SMART_CONTRACT_PATH).toString()));
                    } else {
                        installProposalRequest.setSmartContractInputStream(Util.generateTarGzInputStream(
                                (Paths.get(TEST_FIXTURES_PATH, SMART_CONTRACT_FILEPATH).toFile()),
                                "src"));
                    }
                }

                installProposalRequest.setSmartContractVersion(SMART_CONTRACT_VERSION);
                installProposalRequest.setSmartContractLanguage(SMART_CONTRACT_LANG);

                out("Sending install proposal");

                ////////////////////////////
                // only a client from the same org as the peer can issue an install request
                int numInstallProposal = 0;
                //    Set<String> orgs = orgNodes.keySet();
                //   for (SampleOrg org : testSampleOrgs) {

                Collection<Node> peers = channel.getNodes();
                numInstallProposal = numInstallProposal + peers.size();
                responses = client.sendInstallProposal(installProposalRequest, peers);

                for (ProposalResponse response : responses) {
                    if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                        out("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getNode().getName());
                        successful.add(response);
                    } else {
                        failed.add(response);
                    }
                }

                //   }
                out("Received %d install proposal responses. Successful+verified: %d . Failed: %d", numInstallProposal, successful.size(), failed.size());

                if (failed.size() > 0) {
                    ProposalResponse first = failed.iterator().next();
                    fail("Not enough endorsers for install :" + successful.size() + ".  " + first.getMessage());
                }
            }

            //   client.setUserContext(sampleOrg.getUser(TEST_ADMIN_NAME));
            //  final SmartContractID chaincodeID = firstInstallProposalResponse.getSmartContractID();
            // Note installing chaincode does not require transaction no need to
            // send to Consenters

            ///////////////
            //// Instantiate chaincode.
            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();
            instantiateProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
            instantiateProposalRequest.setSmartContractID(chaincodeID);
            instantiateProposalRequest.setSmartContractLanguage(SMART_CONTRACT_LANG);
            instantiateProposalRequest.setFcn("init");
            instantiateProposalRequest.setArgs(new String[] {"a", "500", "b", "" + (200 + delta)});
            Map<String, byte[]> tm = new HashMap<>();
            tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequest.setTransientMap(tm);

            /*
              policy OR(Org1MSP.member, Org2MSP.member) meaning 1 signature from someone in either Org1 or Org2
              See README.md SmartContract endorsement policies section for more details.
            */
            SmartContractEndorsementPolicy chaincodeEndorsementPolicy = new SmartContractEndorsementPolicy();
            chaincodeEndorsementPolicy.fromYamlFile(new File(TEST_FIXTURES_PATH + "/sdkintegration/chaincodeendorsementpolicy.yaml"));
            instantiateProposalRequest.setSmartContractEndorsementPolicy(chaincodeEndorsementPolicy);

            out("Sending instantiateProposalRequest to all peers with arguments: a and b set to 100 and %s respectively", "" + (200 + delta));
            successful.clear();
            failed.clear();

            if (isFooChain) {  //Send responses both ways with specifying peers and by using those on the channel.
                responses = channel.sendInstantiationProposal(instantiateProposalRequest, channel.getNodes());
            } else {
                responses = channel.sendInstantiationProposal(instantiateProposalRequest);
            }
            for (ProposalResponse response : responses) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successful.add(response);
                    out("Succesful instantiate proposal response Txid: %s from peer %s", response.getTransactionID(), response.getNode().getName());
                } else {
                    failed.add(response);
                }
            }
            out("Received %d instantiate proposal responses. Successful+verified: %d . Failed: %d", responses.size(), successful.size(), failed.size());
            if (failed.size() > 0) {
                for (ProposalResponse fail : failed) {

                    out("Not enough endorsers for instantiate :" + successful.size() + "endorser failed with " + fail.getMessage() + ", on peer" + fail.getNode());

                }
                ProposalResponse first = failed.iterator().next();
                fail("Not enough endorsers for instantiate :" + successful.size() + "endorser failed with " + first.getMessage() + ". Was verified:" + first.isVerified());
            }

            ///////////////
            /// Send instantiate transaction to orderer
            out("Sending instantiateTransaction to orderer with a and b set to 100 and %s respectively", "" + (200 + delta));

            //Specify what events should complete the interest in this transaction. This is the default
            // for all to complete. It's possible to specify many different combinations like
            //any from a group, all from one group and just one from another or even None(NOfEvents.createNoEvents).
            // See. Group.NOfEvents
            Group.NOfEvents nOfEvents = createNofEvents();
            if (!channel.getNodes(EnumSet.of(NodeRole.EVENT_SOURCE)).isEmpty()) {
                nOfEvents.addNodes(channel.getNodes(EnumSet.of(NodeRole.EVENT_SOURCE)));
            }
            if (!channel.getEventHubs().isEmpty()) {
                nOfEvents.addEventHubs(channel.getEventHubs());
            }

            channel.sendTransaction(successful, createTransactionOptions() //Basically the default options but shows it's usage.
                    .userContext(client.getUserContext()) //could be a different user context. this is the default.
                    .shuffleOrders(false) // don't shuffle any orderers the default is true.
                    .orderers(channel.getConsenters()) // specify the orderers we want to try this transaction. Fails once all Consenters are tried.
                    .nOfEvents(nOfEvents) // The events to signal the completion of the interest in the transaction
            ).thenApply(transactionEvent -> {

                waitOnFabric(0);

                assertTrue(transactionEvent.isValid()); // must be valid to be here.
                assertNotNull(transactionEvent.getSignature()); //musth have a signature.
                BlockEvent blockEvent = transactionEvent.getBlockEvent(); // This is the blockevent that has this transaction.
                assertNotNull(blockEvent.getBlock()); // Make sure the RAW Fabric block is returned.

                out("Finished instantiate transaction with transaction id %s", transactionEvent.getTransactionID());

                try {
                    assertEquals(blockEvent.getGroupId(), channel.getName());
                    successful.clear();
                    failed.clear();

                    client.setUserContext(sampleOrg.getUser(TESTUSER_1_NAME));

                    ///////////////
                    /// Send transaction proposal to all peers
                    TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
                    transactionProposalRequest.setSmartContractID(chaincodeID);
                    transactionProposalRequest.setSmartContractLanguage(SMART_CONTRACT_LANG);
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

                    out("sending transactionProposal to all peers with arguments: move(a,b,100)");

                    Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposal(transactionProposalRequest, channel.getNodes());
                    for (ProposalResponse response : transactionPropResp) {
                        if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                            out("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getNode().getName());
                            successful.add(response);
                        } else {
                            failed.add(response);
                        }
                    }

                    // Check that all the proposals are consistent with each other. We should have only one set
                    // where all the proposals above are consistent. Note the when sending to Consenter this is done automatically.
                    //  Shown here as an example that applications can invoke and select.
                    // See org.bcia.javachain.sdk.proposal.consistency_validation config property.
                    Collection<Set<ProposalResponse>> proposalConsistencySets = SDKUtils.getProposalConsistencySets(transactionPropResp);
                    if (proposalConsistencySets.size() != 1) {
                        fail(format("Expected only one set of consistent proposal responses but got %d", proposalConsistencySets.size()));
                    }

                    out("Received %d transaction proposal responses. Successful+verified: %d . Failed: %d",
                            transactionPropResp.size(), successful.size(), failed.size());
                    if (failed.size() > 0) {
                        ProposalResponse firstTransactionProposalResponse = failed.iterator().next();
                        fail("Not enough endorsers for invoke(move a,b,100):" + failed.size() + " endorser error: " +
                                firstTransactionProposalResponse.getMessage() +
                                ". Was verified: " + firstTransactionProposalResponse.isVerified());
                    }
                    out("Successfully received transaction proposal responses.");

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

                    assertEquals(SMART_CONTRACT_NAME, cid.getName());
                    assertEquals(SMART_CONTRACT_VERSION, cid.getVersion());

                    ////////////////////////////
                    // Send Transaction Transaction to orderer
                    out("Sending chaincode transaction(move a,b,100) to orderer.");
                    return channel.sendTransaction(successful).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);

                } catch (Exception e) {
                    out("Caught an exception while invoking chaincode");
                    e.printStackTrace();
                    fail("Failed invoking chaincode with error : " + e.getMessage());
                }

                return null;

            }).thenApply(transactionEvent -> {
                try {

                    waitOnFabric(0);

                    assertTrue(transactionEvent.isValid()); // must be valid to be here.
                    out("Finished transaction with transaction id %s", transactionEvent.getTransactionID());
                    testTxID = transactionEvent.getTransactionID(); // used in the channel queries later

                    ////////////////////////////
                    // Send Query Proposal to all peers
                    //
                    String expect = "" + (300 + delta);
                    out("Now query chaincode for the value of b.");
                    QueryBySmartContractRequest queryBySmartContractRequest = client.newQueryProposalRequest();
                    queryBySmartContractRequest.setArgs(new String[] {"b"});
                    queryBySmartContractRequest.setFcn("query");
                    queryBySmartContractRequest.setSmartContractID(chaincodeID);

                    Map<String, byte[]> tm2 = new HashMap<>();
                    tm2.put("HyperLedgerFabric", "QueryBySmartContractRequest:JavaSDK".getBytes(UTF_8));
                    tm2.put("method", "QueryBySmartContractRequest".getBytes(UTF_8));
                    queryBySmartContractRequest.setTransientMap(tm2);

                    Collection<ProposalResponse> queryProposals = channel.queryBySmartContract(queryBySmartContractRequest, channel.getNodes());
                    for (ProposalResponse proposalResponse : queryProposals) {
                        if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                            fail("Failed query proposal from peer " + proposalResponse.getNode().getName() + " status: " + proposalResponse.getStatus() +
                                    ". Messages: " + proposalResponse.getMessage()
                                    + ". Was verified : " + proposalResponse.isVerified());
                        } else {
                            String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                            out("Query payload of b from peer %s returned %s", proposalResponse.getNode().getName(), payload);
                            assertEquals(payload, expect);
                        }
                    }

                    return null;
                } catch (Exception e) {
                    out("Caught exception while running query");
                    e.printStackTrace();
                    fail("Failed during chaincode query with error : " + e.getMessage());
                }

                return null;
            }).exceptionally(e -> {
                if (e instanceof TransactionEventException) {
                    BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                    if (te != null) {
                        throw new AssertionError(format("Transaction with txid %s failed. %s", te.getTransactionID(), e.getMessage()), e);
                    }
                }

                throw new AssertionError(format("Test failed with %s exception %s", e.getClass().getName(), e.getMessage()), e);

            }).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);

            // Group queries

            // We can only send channel queries to peers that are in the same org as the SDK user context
            // Get the peers from the current org being used and pick one randomly to send the queries to.
            //  Set<Node> peerSet = sampleOrg.getNodes();
            //  Node queryNode = peerSet.iterator().next();
            //   out("Using peer %s for channel queries", queryNode.getName());

            BlockchainInfo channelInfo = channel.queryBlockchainInfo();
            out("Group info for : " + channelName);
            out("Group height: " + channelInfo.getHeight());
            String chainCurrentHash = Hex.encodeHexString(channelInfo.getCurrentBlockHash());
            String chainPreviousHash = Hex.encodeHexString(channelInfo.getPreviousBlockHash());
            out("Chain current block hash: " + chainCurrentHash);
            out("Chainl previous block hash: " + chainPreviousHash);

            // Query by block number. Should return latest block, i.e. block number 2
            BlockInfo returnedBlock = channel.queryBlockByNumber(channelInfo.getHeight() - 1);
            String previousHash = Hex.encodeHexString(returnedBlock.getPreviousHash());
            out("queryBlockByNumber returned correct block with blockNumber " + returnedBlock.getBlockNumber()
                    + " \n previous_hash " + previousHash);
            assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());
            assertEquals(chainPreviousHash, previousHash);

            // Query by block hash. Using latest block's previous hash so should return block number 1
            byte[] hashQuery = returnedBlock.getPreviousHash();
            returnedBlock = channel.queryBlockByHash(hashQuery);
            out("queryBlockByHash returned block with blockNumber " + returnedBlock.getBlockNumber());
            assertEquals(channelInfo.getHeight() - 2, returnedBlock.getBlockNumber());

            // Query block by TxID. Since it's the last TxID, should be block 2
            returnedBlock = channel.queryBlockByTransactionID(testTxID);
            out("queryBlockByTxID returned block with blockNumber " + returnedBlock.getBlockNumber());
            assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());

            // query transaction by ID
            TransactionInfo txInfo = channel.queryTransactionByID(testTxID);
            out("QueryTransactionByID returned TransactionInfo: txID " + txInfo.getTransactionID()
                    + "\n     validation code " + txInfo.getValidationCode().getNumber());

            if (chaincodeEventListenerHandle != null) {

                channel.unregisterSmartContractEventListener(chaincodeEventListenerHandle);
                //Should be two. One event in chaincode and two notification for each of the two event hubs

                final int numberEventsExpected = channel.getEventHubs().size() +
                        channel.getNodes(EnumSet.of(NodeRole.EVENT_SOURCE)).size();
                //just make sure we get the notifications.
                for (int i = 15; i > 0; --i) {
                    if (chaincodeEvents.size() == numberEventsExpected) {
                        break;
                    } else {
                        Thread.sleep(90); // wait for the events.
                    }

                }
                assertEquals(numberEventsExpected, chaincodeEvents.size());

                for (SmartContractEventCapture chaincodeEventCapture : chaincodeEvents) {
                    assertEquals(chaincodeEventListenerHandle, chaincodeEventCapture.handle);
                    assertEquals(testTxID, chaincodeEventCapture.chaincodeEvent.getTxId());
                    assertEquals(EXPECTED_EVENT_NAME, chaincodeEventCapture.chaincodeEvent.getEventName());
                    assertTrue(Arrays.equals(EXPECTED_EVENT_DATA, chaincodeEventCapture.chaincodeEvent.getPayload()));
                    assertEquals(SMART_CONTRACT_NAME, chaincodeEventCapture.chaincodeEvent.getSmartContractId());

                    BlockEvent blockEvent = chaincodeEventCapture.blockEvent;
                    assertEquals(channelName, blockEvent.getGroupId());
                    //   assertTrue(channel.getEventHubs().contains(blockEvent.getEventHub()));

                }

            } else {
                assertTrue(chaincodeEvents.isEmpty());
            }

            out("Running for Group %s done", channelName);

        } catch (Exception e) {
            out("Caught an exception running channel %s", channel.getName());
            e.printStackTrace();
            fail("Test failed with error : " + e.getMessage());
        }
    }

    /**
     * 构建群组
     * @param name
     * @param client
     * @param sampleOrg
     * @return
     * @throws Exception
     */
    Group constructGroup(String name, HFClient client, SampleOrg sampleOrg) throws Exception {
        ////////////////////////////
        //构建群组
        //

        out("Constructing group %s", name);

        //boolean doNodeEventing = false;
//        boolean doNodeEventing = !testConfig.isRunningAgainstFabric10() && BAR_CHANNEL_NAME.equals(name);
        boolean doNodeEventing = !testConfig.isRunningAgainstFabric10() && FOO_CHANNEL_NAME.equals(name);
        //Only peer Admin org
        client.setUserContext(sampleOrg.getNodeAdmin());

        Collection<Consenter> orderers = new LinkedList<>();

        //循环consenter名称设置属性
        for (String orderName : sampleOrg.getConsenterNames()) {

            Properties ordererProperties = testConfig.getConsenterProperties(orderName);

            //example of setting keepAlive to avoid timeouts on inactive http2 connections.
            // Under 5 minutes would require changes to server side to accept faster ping rates.
            ordererProperties.put("grpc.NettyGroupBuilderOption.keepAliveTime", new Object[] {5L, TimeUnit.MINUTES});
            ordererProperties.put("grpc.NettyGroupBuilderOption.keepAliveTimeout", new Object[] {8L, TimeUnit.SECONDS});
            ordererProperties.put("grpc.NettyGroupBuilderOption.keepAliveWithoutCalls", new Object[] {true});

            if (!clientTLSProperties.isEmpty()) {
                ordererProperties.putAll(clientTLSProperties.get(sampleOrg.getName()));
            }

            orderers.add(client.newConsenter(orderName, sampleOrg.getConsenterLocation(orderName), ordererProperties));
        }

        //只需选择列表中的第一个订单即可创建群组

        Consenter anConsenter = orderers.iterator().next();
        orderers.remove(anConsenter);

        //GroupConfiguration channelConfiguration = new GroupConfiguration(new File("/home/bcia/javachain-sdk-ftsafe/src/test/fixture/sdkintegration/e2e-2Orgs/v1.1/myGroup.tx"));
        GroupConfiguration channelConfiguration = null;
        //创建只有一个签名者的群组，该签名者是此orgs node admin。如果群组创建策略需要更多签名，则还需要添加它们。
        Group newGroup = client.newGroup(name, anConsenter, channelConfiguration, client.getGroupConfigurationSignature(channelConfiguration, sampleOrg.getNodeAdmin()));

        out("Created group %s", name);
        //if (true) return newGroup;//创建后截止
        boolean everyother = true; //test with both cases when doing peer eventing.
        for (String peerName : sampleOrg.getNodeNames()) {
            String peerLocation = sampleOrg.getNodeLocation(peerName);

            Properties peerProperties = testConfig.getNodeProperties(peerName); //test properties for peer.. if any.
            if (peerProperties == null) {
                peerProperties = new Properties();
            }

            if (!clientTLSProperties.isEmpty()) {
                peerProperties.putAll(clientTLSProperties.get(sampleOrg.getName()));
            }

            //Example of setting specific options on grpc's NettyGroupBuilder
            peerProperties.put("grpc.NettyGroupBuilderOption.maxInboundMessageSize", 9000000);
            out("step 1 newNode start");
            Node peer = client.newNode(peerName, peerLocation, peerProperties);
            out("step 2 newNode end");
            if (doNodeEventing && everyother) {
            	out("step 3 joinNode default");
                newGroup.joinNode(peer, createNodeOptions()); //Default is all roles.
            } else {
            	out("step 4 joinNode no event");
                // Set peer to not be all roles but eventing.
                newGroup.joinNode(peer, createNodeOptions().setNodeRoles(NodeRole.NO_EVENT_SOURCE));
            }
            out("step 5 joinNode end Node %s joined group %s", peerName, name);
            everyother = !everyother;
        }
        //just for testing ...
        if (doNodeEventing) {
            // Make sure there is one of each type peer at the very least.
            assertFalse(newGroup.getNodes(EnumSet.of(NodeRole.EVENT_SOURCE)).isEmpty());
            assertFalse(newGroup.getNodes(NodeRole.NO_EVENT_SOURCE).isEmpty());
        }

        for (Consenter orderer : orderers) { //add remaining orderers if any.
            newGroup.addConsenter(orderer);
        }

        for (String eventHubName : sampleOrg.getEventHubNames()) {

            final Properties eventHubProperties = testConfig.getEventHubProperties(eventHubName);

            eventHubProperties.put("grpc.NettyGroupBuilderOption.keepAliveTime", new Object[] {5L, TimeUnit.MINUTES});
            eventHubProperties.put("grpc.NettyGroupBuilderOption.keepAliveTimeout", new Object[] {8L, TimeUnit.SECONDS});

            if (!clientTLSProperties.isEmpty()) {
                eventHubProperties.putAll(clientTLSProperties.get(sampleOrg.getName()));
            }

            EventHub eventHub = client.newEventHub(eventHubName, sampleOrg.getEventHubLocation(eventHubName),
                    eventHubProperties);
            newGroup.addEventHub(eventHub);
        }

        newGroup.initialize();

        out("Finished initialization channel %s", name);

        //Just checks if channel can be serialized and deserialized .. otherwise this is just a waste :)
        byte[] serializedGroupBytes = newGroup.serializeGroup();
        newGroup.shutdown(true);

        return client.deSerializeGroup(serializedGroupBytes).initialize();

    }

    private void waitOnFabric(int additional) {
        //NOOP today

    }

    void blockWalker(HFClient client, Group channel) throws InvalidArgumentException, ProposalException, IOException {
        try {
            BlockchainInfo channelInfo = channel.queryBlockchainInfo();

            for (long current = channelInfo.getHeight() - 1; current > -1; --current) {
                BlockInfo returnedBlock = channel.queryBlockByNumber(current);
                final long blockNumber = returnedBlock.getBlockNumber();

                out("current block number %d has data hash: %s", blockNumber, Hex.encodeHexString(returnedBlock.getDataHash()));
                out("current block number %d has previous hash id: %s", blockNumber, Hex.encodeHexString(returnedBlock.getPreviousHash()));
                out("current block number %d has calculated block hash is %s", blockNumber, Hex.encodeHexString(SDKUtils.calculateBlockHash(client,
                        blockNumber, returnedBlock.getPreviousHash(), returnedBlock.getDataHash())));

                final int envelopeCount = returnedBlock.getEnvelopeCount();
                assertEquals(1, envelopeCount);
                out("current block number %d has %d envelope count:", blockNumber, returnedBlock.getEnvelopeCount());
                int i = 0;
                for (BlockInfo.EnvelopeInfo envelopeInfo : returnedBlock.getEnvelopeInfos()) {
                    ++i;

                    out("  Transaction number %d has transaction id: %s", i, envelopeInfo.getTransactionID());
                    final String channelId = envelopeInfo.getGroupId();
                    assertTrue("foo".equals(channelId) || "bar".equals(channelId));

                    out("  Transaction number %d has channel id: %s", i, channelId);
                    out("  Transaction number %d has epoch: %d", i, envelopeInfo.getEpoch());
                    out("  Transaction number %d has transaction timestamp: %tB %<te,  %<tY  %<tT %<Tp", i, envelopeInfo.getTimestamp());
                    out("  Transaction number %d has type id: %s", i, "" + envelopeInfo.getType());
                    out("  Transaction number %d has nonce : %s", i, "" + Hex.encodeHexString(envelopeInfo.getNonce()));
                    out("  Transaction number %d has submitter mspid: %s,  certificate: %s", i, envelopeInfo.getCreator().getMspid(), envelopeInfo.getCreator().getId());

                    if (envelopeInfo.getType() == TRANSACTION_ENVELOPE) {
                        BlockInfo.TransactionEnvelopeInfo transactionEnvelopeInfo = (BlockInfo.TransactionEnvelopeInfo) envelopeInfo;

                        out("  Transaction number %d has %d actions", i, transactionEnvelopeInfo.getTransactionActionInfoCount());
                        assertEquals(1, transactionEnvelopeInfo.getTransactionActionInfoCount()); // for now there is only 1 action per transaction.
                        out("  Transaction number %d isValid %b", i, transactionEnvelopeInfo.isValid());
                        assertEquals(transactionEnvelopeInfo.isValid(), true);
                        out("  Transaction number %d validation code %d", i, transactionEnvelopeInfo.getValidationCode());
                        assertEquals(0, transactionEnvelopeInfo.getValidationCode());

                        int j = 0;
                        for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo transactionActionInfo : transactionEnvelopeInfo.getTransactionActionInfos()) {
                            ++j;
                            out("   Transaction action %d has response status %d", j, transactionActionInfo.getResponseStatus());
                            assertEquals(200, transactionActionInfo.getResponseStatus());
                            out("   Transaction action %d has response message bytes as string: %s", j,
                                    printableString(new String(transactionActionInfo.getResponseMessageBytes(), "UTF-8")));
                            out("   Transaction action %d has %d endorsements", j, transactionActionInfo.getEndorsementsCount());
                            assertEquals(2, transactionActionInfo.getEndorsementsCount());

                            for (int n = 0; n < transactionActionInfo.getEndorsementsCount(); ++n) {
                                BlockInfo.EndorserInfo endorserInfo = transactionActionInfo.getEndorsementInfo(n);
                                out("Endorser %d signature: %s", n, Hex.encodeHexString(endorserInfo.getSignature()));
                                out("Endorser %d endorser: mspid %s \n certificate %s", n, endorserInfo.getMspid(), endorserInfo.getId());
                            }
                            out("   Transaction action %d has %d chaincode input arguments", j, transactionActionInfo.getSmartContractInputArgsCount());
                            for (int z = 0; z < transactionActionInfo.getSmartContractInputArgsCount(); ++z) {
                                out("     Transaction action %d has chaincode input argument %d is: %s", j, z,
                                        printableString(new String(transactionActionInfo.getSmartContractInputArgs(z), "UTF-8")));
                            }

                            out("   Transaction action %d proposal response status: %d", j,
                                    transactionActionInfo.getProposalResponseStatus());
                            out("   Transaction action %d proposal response payload: %s", j,
                                    printableString(new String(transactionActionInfo.getProposalResponsePayload())));

                            // Check to see if we have our expected event.
                            if (blockNumber == 2) {
                                SmartContractEvent chaincodeEvent = transactionActionInfo.getEvent();
                                assertNotNull(chaincodeEvent);

                                assertTrue(Arrays.equals(EXPECTED_EVENT_DATA, chaincodeEvent.getPayload()));
                                assertEquals(testTxID, chaincodeEvent.getTxId());
                                assertEquals(SMART_CONTRACT_NAME, chaincodeEvent.getSmartContractId());
                                assertEquals(EXPECTED_EVENT_NAME, chaincodeEvent.getEventName());

                            }

                            TxReadWriteSetInfo rwsetInfo = transactionActionInfo.getTxReadWriteSet();
                            if (null != rwsetInfo) {
                                out("   Transaction action %d has %d name space read write sets", j, rwsetInfo.getNsRwsetCount());

                                for (TxReadWriteSetInfo.NsRwsetInfo nsRwsetInfo : rwsetInfo.getNsRwsetInfos()) {
                                    final String namespace = nsRwsetInfo.getNamespace();
                                    KvRwset.KVRWSet rws = nsRwsetInfo.getRwset();

                                    int rs = -1;
                                    for (KvRwset.KVRead readList : rws.getReadsList()) {
                                        rs++;

                                        out("     Namespace %s read set %d key %s  version [%d:%d]", namespace, rs, readList.getKey(),
                                                readList.getVersion().getBlockNum(), readList.getVersion().getTxNum());

                                        if ("bar".equals(channelId) && blockNumber == 2) {
                                            if ("example_cc_go".equals(namespace)) {
                                                if (rs == 0) {
                                                    assertEquals("a", readList.getKey());
                                                    assertEquals(1, readList.getVersion().getBlockNum());
                                                    assertEquals(0, readList.getVersion().getTxNum());
                                                } else if (rs == 1) {
                                                    assertEquals("b", readList.getKey());
                                                    assertEquals(1, readList.getVersion().getBlockNum());
                                                    assertEquals(0, readList.getVersion().getTxNum());
                                                } else {
                                                    fail(format("unexpected readset %d", rs));
                                                }

                                                TX_EXPECTED.remove("readset1");
                                            }
                                        }
                                    }

                                    rs = -1;
                                    for (KvRwset.KVWrite writeList : rws.getWritesList()) {
                                        rs++;
                                        String valAsString = printableString(new String(writeList.getValue().toByteArray(), "UTF-8"));

                                        out("     Namespace %s write set %d key %s has value '%s' ", namespace, rs,
                                                writeList.getKey(),
                                                valAsString);

                                        if ("bar".equals(channelId) && blockNumber == 2) {
                                            if (rs == 0) {
                                                assertEquals("a", writeList.getKey());
                                                assertEquals("400", valAsString);
                                            } else if (rs == 1) {
                                                assertEquals("b", writeList.getKey());
                                                assertEquals("400", valAsString);
                                            } else {
                                                fail(format("unexpected writeset %d", rs));
                                            }

                                            TX_EXPECTED.remove("writeset1");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (!TX_EXPECTED.isEmpty()) {
                fail(TX_EXPECTED.get(0));
            }
        } catch (InvalidProtocolBufferRuntimeException e) {
            throw e.getCause();
        }
    }

}
