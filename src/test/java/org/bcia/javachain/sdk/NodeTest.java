/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.bcia.javachain.sdk;

import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.exception.NodeException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class NodeTest {
    static HFClient hfclient = null;
    static Node peer = null;

    static final String PEER_NAME = "peertest";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setupClient() {
        try {
            hfclient = TestHFClient.newInstance();
            peer = hfclient.newNode(PEER_NAME, "grpc://localhost:7051");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testGetName() {
        Assert.assertTrue(peer != null);
        try {
            peer = hfclient.newNode(PEER_NAME, "grpc://localhost:4");
            Assert.assertEquals(PEER_NAME, peer.getName());
        } catch (InvalidArgumentException e) {
            Assert.fail("Unexpected Exeception " + e.getMessage());
        }

    }

    @Test (expected = InvalidArgumentException.class)
    public void testSetNullName() throws InvalidArgumentException {
        peer = hfclient.newNode(null, "grpc://localhost:4");
        Assert.fail("expected set null name to throw exception.");
    }

    @Test (expected = InvalidArgumentException.class)
    public void testSetEmptyName() throws InvalidArgumentException {
        peer = hfclient.newNode("", "grpc://localhost:4");
        Assert.fail("expected set empty name to throw exception.");
    }

    @Test (expected = NodeException.class)
    public void testSendAsyncNullProposal() throws NodeException, InvalidArgumentException {
        peer.sendProposalAsync(null);
    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadURL() throws InvalidArgumentException {
        hfclient.newNode(PEER_NAME, " ");
        Assert.fail("Expected peer with no channel throw exception");
    }

    @Test
    public void testDuplicateGroup() throws InvalidArgumentException {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Can not add peer " + PEER_NAME + " to channel duplicate because it already belongs to channel duplicate.");

        Group duplicate = hfclient.newGroup("duplicate");
        peer.setGroup(duplicate);
        peer.setGroup(duplicate);
    }
}
