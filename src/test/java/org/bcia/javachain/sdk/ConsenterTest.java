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
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.File;

import static org.junit.Assert.fail;


public class ConsenterTest {
    HFClient hfclient = null;
    Consenter orderer = null;
    static File tempFile;

    static final String DEFAULT_CHANNEL_NAME = "channel";
    static final String ORDERER_NAME = "testorderer";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Before
    public void setupClientAndOrder() throws Exception {
        hfclient = TestHFClient.newInstance();
        orderer = hfclient.newConsenter(ORDERER_NAME, "grpc://localhost:5151");
    }

    @AfterClass
    public static void cleanUp() {
        if (tempFile != null) {
            tempFile.delete();
            tempFile = null;
        }
    }

    @Test
    public void testSetDuplicateChannnel() throws InvalidArgumentException {
        //thrown.expect(InvalidArgumentException.class);
        //thrown.expectMessage("Can not add orderer " + ORDERER_NAME + " to channel channel2 because it already belongs to channel channel2.");
        try {
            Group channel2 = hfclient.newGroup("channel2");
            orderer.setGroup(channel2);
            orderer.setGroup(channel2);
        } catch (Exception e) {

            fail("Can not add orderer " + ORDERER_NAME + " to channel channel2 because it already belongs to channel channel2.");
        }
    }

    @Test
    public void testSetNullGroup() throws InvalidArgumentException {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("setGroup Group can not be null");

        orderer.setGroup(null);
    }

    @Test
    public void testSetGroup() {

        try {
            Group channel = hfclient.newGroup(DEFAULT_CHANNEL_NAME);
            orderer.setGroup(channel);
            Assert.assertTrue(channel == orderer.getGroup());

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testNullConsenterName() throws InvalidArgumentException {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Invalid name for orderer");

        new Consenter(null, "url", null);
    }

    @Test(expected = InvalidArgumentException.class)
    public void testBadAddress() throws InvalidArgumentException {
        orderer = hfclient.newConsenter("badorderer", "xxxxxx");
        fail("Consenter did not allow setting bad URL.");
    }

    @Test(expected = InvalidArgumentException.class)
    public void testMissingAddress() throws InvalidArgumentException {
        orderer = hfclient.newConsenter("badaddress", "");
        fail("Consenter did not allow setting a missing address.");
    }

    @Ignore
    public void testGetGroup() {
        try {
            Group channel = hfclient.newGroup(DEFAULT_CHANNEL_NAME);
            orderer = hfclient.newConsenter("ordererName", "grpc://localhost:5151");
            channel.addConsenter(orderer);
        } catch (Exception e) {
            fail("Unexpected Exception " + e.getMessage());
        }
        Assert.assertTrue("Test passed - ", orderer.getGroup().getName().equalsIgnoreCase(DEFAULT_CHANNEL_NAME));
    }

    @Test(expected = Exception.class)
    public void testSendNullTransactionThrowsException() throws Exception {
        try {
            orderer = hfclient.newConsenter(ORDERER_NAME, "grpc://localhost:5151");
        } catch (InvalidArgumentException e) {
            fail("Failed to create new orderer: " + e);
        }
        orderer.sendTransaction(null);
        fail("Transaction should not be null.");
    }

}
