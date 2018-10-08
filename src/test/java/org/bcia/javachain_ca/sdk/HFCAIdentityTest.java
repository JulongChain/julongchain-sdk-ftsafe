/*
 *  Copyright 2016, 2017, 2018 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.bcia.javachain_ca.sdk;


public class HFCAIdentityTest {

    /*@Rule
    public ExpectedException thrown = ExpectedException.none();

    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TEST_ADMIN_ORG = "org1";

    private SampleStore sampleStore;
    SampleUser admin;

    private static CryptoPrimitives crypto;

    @BeforeClass
    public static void setupBeforeClass() {
        try {
            crypto = new CryptoPrimitives();
            crypto.init();
        } catch (Exception e) {
            throw new RuntimeException("HFCAIdentityTest.setupBeforeClass failed!", e);
        }
    }

    @Before
    public void setup() throws CryptoException, InvalidArgumentException,
            org.bcia.javachain.sdk.exception.InvalidArgumentException, MalformedURLException, EnrollmentException {

        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        if (sampleStoreFile.exists()) { // For testing start fresh
            sampleStoreFile.delete();
        }
        sampleStore = new SampleStore(sampleStoreFile);
        sampleStoreFile.deleteOnExit();

        // SampleUser can be any implementation that implements org.bcia.javachain.sdk.User Interface
        admin = sampleStore.getMember(TEST_ADMIN_NAME, TEST_ADMIN_ORG);

    }

    @Test
    public void testHFCAIdentityNewInstance() throws Exception {

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);
        HFCAIdentity ident = client.newHFCAIdentity("testid");

        Assert.assertNotNull(ident);
        Assert.assertSame(HFCAIdentity.class, ident.getClass());
        Assert.assertEquals(ident.getEnrollmentId(), "testid");
    }

    @Test
    public void testHFCAIdentityCryptoNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Client's crypto primitives not set");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(null);
        HFCAIdentity ident = client.newHFCAIdentity("testid");
    }

    @Test
    public void testHFCAIdentityIDNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("EnrollmentID cannot be null or empty");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        HFCAIdentity ident = client.newHFCAIdentity(null);
    }

    @Test
    public void getIdentityNoServerResponse() throws Exception {

        thrown.expect(IdentityException.class);
        thrown.expectMessage("Error while getting user");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);

        HFCAIdentity ident = client.newHFCAIdentity("testuser1");
        ident.read(admin);
    }

    @Test
    public void createIdentityNoServerResponse() throws Exception {

        thrown.expect(IdentityException.class);
        thrown.expectMessage("Error while creating user");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);

        HFCAIdentity ident = client.newHFCAIdentity("testuser1");
        ident.create(admin);
    }

    @Test
    public void updateIdentityNoServerResponse() throws Exception {

        thrown.expect(IdentityException.class);
        thrown.expectMessage("Error while updating user");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);

        HFCAIdentity ident = client.newHFCAIdentity("testuser1");
        ident.update(admin);
    }

    @Test
    public void deleteIdentityNoServerResponse() throws Exception {

        thrown.expect(IdentityException.class);
        thrown.expectMessage("Error while deleting user");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);

        HFCAIdentity ident = client.newHFCAIdentity("testuser1");
        ident.delete(admin);
    }*/
}
