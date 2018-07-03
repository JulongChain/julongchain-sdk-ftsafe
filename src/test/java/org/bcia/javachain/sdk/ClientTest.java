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

package org.bcia.javachain.sdk;


import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.helper.Config;
import org.bcia.javachain.sdk.security.CryptoSuite;
import org.bcia.javachain.sdk.testutils.TestUtils;
import org.bcia.javachain.sdk.testutils.TestUtils.MockEnrollment;
import org.bcia.javachain.sdk.testutils.TestUtils.MockUser;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import static org.bcia.javachain.sdk.testutils.TestUtils.resetConfig;

public class ClientTest {
    private static final String CHANNEL_NAME = "channel1";
    static HFClient hfclient = null;

    private static final String USER_NAME = "MockMe";
    private static final String USER_MSP_ID = "MockMSPID";


    @BeforeClass
    public static void setupClient() throws Exception {
        try {
            resetConfig();
            hfclient = TestHFClient.newInstance();

        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());

        }

    }

    @Test
    public void testNewGroup() {
        try {
            Group testGroup = hfclient.newGroup(CHANNEL_NAME);
            Assert.assertTrue(testGroup != null && CHANNEL_NAME.equalsIgnoreCase(testGroup.getName()));
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test (expected = InvalidArgumentException.class)
    public void testSetNullGroup() throws InvalidArgumentException {
        hfclient.newGroup(null);
        Assert.fail("Expected null channel to throw exception.");
    }

    @Test
    public void testNewNode() {
        try {
            Node peer = hfclient.newNode("peer_", "grpc://localhost:7051");
            Assert.assertTrue(peer != null);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadURL() throws InvalidArgumentException {
        hfclient.newNode("peer_", " ");
        Assert.fail("Expected peer with no channel throw exception");
    }

    @Test
    public void testNewConsenter() {
        try {
            Consenter orderer = hfclient.newConsenter("xx", "grpc://localhost:5005");
            Assert.assertTrue(orderer != null);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadAddress() throws InvalidArgumentException {
        hfclient.newConsenter("xx", "xxxxxx");
        Assert.fail("Consenter allowed setting bad URL.");
    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadCryptoSuite() throws InvalidArgumentException {
        HFClient.createNewInstance()
                .newConsenter("xx", "xxxxxx");
        Assert.fail("Consenter allowed setting no cryptoSuite");
    }

    @Test
    public void testGoodMockUser() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        client.setUserContext(TestUtils.getMockUser(USER_NAME, USER_MSP_ID));
        Consenter orderer = hfclient.newConsenter("justMockme", "grpc://localhost:99"); // test mock should work.
        Assert.assertNotNull(orderer);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserContextNull() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        client.setUserContext(null);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserNameNull() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(null, USER_MSP_ID);

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserNameEmpty() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser("", USER_MSP_ID);

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserMSPIDNull() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(USER_NAME, null);

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserMSPIDEmpty() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(USER_NAME, "");

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadEnrollmentNull() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(USER_NAME, USER_MSP_ID);
        mockUser.setEnrollment(null);

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadEnrollmentBadCert() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(USER_NAME, USER_MSP_ID);

        MockEnrollment mockEnrollment = TestUtils.getMockEnrollment(null);
        mockUser.setEnrollment(mockEnrollment);

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadEnrollmentBadKey() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());


        MockUser mockUser = TestUtils.getMockUser(USER_NAME, USER_MSP_ID);

        MockEnrollment mockEnrollment = TestUtils.getMockEnrollment(null, "mockCert");
        mockUser.setEnrollment(mockEnrollment);

        client.setUserContext(mockUser);

    }

    @Test //(expected = InvalidArgumentException.class)
    @Ignore
    public void testCryptoFactory() throws Exception {
        try {
            resetConfig();
            Assert.assertNotNull(Config.getConfig().getDefaultCryptoSuiteFactory());

            HFClient client = HFClient.createNewInstance();

            client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            MockUser mockUser = TestUtils.getMockUser(USER_NAME, USER_MSP_ID);

            MockEnrollment mockEnrollment = TestUtils.getMockEnrollment(null, "mockCert");
            mockUser.setEnrollment(mockEnrollment);

            client.setUserContext(mockUser);
        } finally {
            System.getProperties().remove("org.bcia.javachain.sdk.crypto.default_crypto_suite_factory");

        }

    }

}
