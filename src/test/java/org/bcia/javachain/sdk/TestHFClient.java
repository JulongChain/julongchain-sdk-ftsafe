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

package org.bcia.javachain.sdk;

import org.bcia.javachain.common.exception.JavaChainException;
import org.bcia.javachain.sdk.HFClient;
import org.bcia.javachain.sdk.helper.MspStore;
import org.bcia.javachain.sdk.security.csp.intfs.IKey;
import org.bcia.javachain.sdk.security.gm.CertificateUtils;
import org.bcia.javachain.sdk.testutils.TestConfig;
import org.bcia.javachain.sdkintegration.SampleOrg;
import org.bcia.javachain.sdkintegration.SampleStore;
import org.bcia.javachain.sdkintegration.SampleUser;
import org.bcia.javachain_ca.sdk.RegistrationRequest;

import java.io.File;
import java.util.Collection;

import static java.lang.String.format;

public class TestHFClient {


    public static final String TEST_ADMIN_NAME = "admin";
    public static final String TESTUSER_1_NAME = "user1";


    final File tempFile;
    final HFClient hfClient;

    public TestHFClient(File tempFile, HFClient hfClient) {
        this.tempFile = tempFile;
        this.hfClient = hfClient;
    }

    public static HFClient newInstance() throws Exception {

        HFClient hfclient = HFClient.createNewInstance();
        setupClient(hfclient);

        return hfclient;
    }

    public static void setupClient(HFClient hfclient) throws Exception {

        File tempFile = File.createTempFile("teststore", "properties");
        tempFile.deleteOnExit();

        File sampleStoreFile = new File(System.getProperty("user.home") + "/test.properties");
        if (sampleStoreFile.exists()) { //For testing start fresh
            sampleStoreFile.delete();
        }
        final SampleStore sampleStore = new SampleStore(sampleStoreFile);

        Collection<SampleOrg> sampleOrgs = TestConfig.getConfig().getIntegrationTestsSampleOrgs();
        SampleOrg sampleOrg = sampleOrgs.toArray(new SampleOrg[0])[0];
        initUser(sampleOrgs, sampleStore);
        hfclient.setUserContext(sampleOrg.getNodeAdmin());
    }

    static File findFileSk(String directorys) {

        File directory = new File(directorys);

        File[] matches = directory.listFiles((dir, name) -> name.endsWith("_sk"));

        if (null == matches) {
            throw new RuntimeException(format("Matches returned null does %s directory exist?", directory.getAbsoluteFile().getName()));
        }

        if (matches.length != 1) {
            throw new RuntimeException(format("Expected in %s only 1 sk file but found %d", directory.getAbsoluteFile().getName(), matches.length));
        }

        return matches[0];

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


    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        if (tempFile != null) {
            try {
                tempFile.delete();
            } catch (Exception e) {
                // // now harm done.
            }
        }
    }
}
