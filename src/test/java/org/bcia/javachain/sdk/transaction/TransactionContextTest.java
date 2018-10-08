/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.bcia.javachain.sdk.transaction;

import com.google.protobuf.ByteString;
import org.bcia.javachain.common.exception.JavaChainException;
import org.bcia.javachain.sdk.*;
import org.bcia.javachain.sdk.helper.MspStore;
import org.bcia.javachain.sdk.security.csp.intfs.IKey;
import org.bcia.javachain.sdk.security.gm.CertificateUtils;
import org.bcia.javachain.sdk.testutils.TestConfig;
import org.bcia.javachain.sdkintegration.SampleOrg;
import org.bcia.javachain.sdkintegration.SampleStore;
import org.bcia.javachain.sdkintegration.SampleUser;
import org.bcia.javachain_ca.sdk.RegistrationRequest;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.lang.reflect.Constructor;
import java.util.Collection;

public class TransactionContextTest {

    public static final String TEST_ADMIN_NAME = "admin";
    public static final String TESTUSER_1_NAME = "user1";

    public final TemporaryFolder tempFolder = new TemporaryFolder();
    static HFClient hfclient = null;

    @BeforeClass
    public static void setupClient() {

        File sampleStoreFile = new File(System.getProperty("user.home") + "/test.properties");
        if (sampleStoreFile.exists()) { //For testing start fresh
            sampleStoreFile.delete();
        }
        final SampleStore sampleStore = new SampleStore(sampleStoreFile);

        try {
            hfclient = TestHFClient.newInstance();
            Collection<SampleOrg> sampleOrgs = TestConfig.getConfig().getIntegrationTestsSampleOrgs();
            SampleOrg sampleOrg = sampleOrgs.toArray(new SampleOrg[0])[0];
            initUser(sampleOrgs, sampleStore);
            hfclient.setUserContext(sampleOrg.getNodeAdmin());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());

        }
    }

    /**
     * 测试签名
     * @throws Exception
     */
    @Test
    public void testSignByteStrings() throws Exception {

        TransactionContext context = createTestContext();

        Assert.assertNull(context.signByteStrings((ByteString) null));
        Assert.assertNull(context.signByteStrings((ByteString[]) null));
        Assert.assertNull(context.signByteStrings(new ByteString[0]));

        User[] users = new User[0];
        Assert.assertNull(context.signByteStrings(users, (ByteString) null));
        Assert.assertNull(context.signByteStrings(users, (ByteString[]) null));
        Assert.assertNull(context.signByteStrings(users, new ByteString[0]));

    }

    // ==========================================================================================
    // Helper methods
    // ==========================================================================================

    /**
     * 创建测试交易上下文
     * @return
     */
    private TransactionContext createTestContext() {
        Group channel = createTestGroup("channel1");
        User user = hfclient.getUserContext();
        return new TransactionContext(channel, user);
    }

    /**
     * 测试群组创建
     * @param channelName
     * @return
     */
    private Group createTestGroup(String channelName) {

        Group channel = null;

        try {
            channel = new Group("channel1", hfclient);
            Constructor<?> constructor = Group.class.getDeclaredConstructor(String.class, HFClient.class);
            constructor.setAccessible(true);
            channel = (Group) constructor.newInstance(channelName, hfclient);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }

        return channel;
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

}
