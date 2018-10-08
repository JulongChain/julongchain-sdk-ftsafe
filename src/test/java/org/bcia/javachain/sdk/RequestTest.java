/*
 *
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.bcia.javachain.sdk;

import org.bcia.javachain.sdk.HFClient;
import org.bcia.javachain.sdk.InstallProposalRequest;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;

import static org.junit.Assert.assertEquals;

public class RequestTest {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    HFClient hfclient;
    InputStream mockstream;
    File someFileLocation = new File("");
    File someFileLocation2 = new File("");

    @Before
    public void setupClient() throws Exception {
        hfclient = HFClient.createNewInstance();
        mockstream = new ByteArrayInputStream(new byte[0]);

    }

    @Test
    public void testinstallProposalRequestStreamWithMeta() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("SmartContract META-INF location may not be set with chaincode input stream set.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setSmartContractInputStream(mockstream);
        installProposalRequest.setSmartContractMetaInfLocation(someFileLocation);

    }

    @Test
    public void testinstallProposalRequestStreamWithSourceLocation() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Error setting chaincode location. SmartContract input stream already set. Only one or the other maybe set.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setSmartContractInputStream(mockstream);
        assertEquals(installProposalRequest.getSmartContractInputStream(), mockstream);
        installProposalRequest.setSmartContractSourceLocation(someFileLocation);

    }

    @Test
    public void testinstallProposalRequestWithLocationSetStream() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Error setting chaincode input stream. SmartContract source location already set. Only one or the other maybe set.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setSmartContractSourceLocation(someFileLocation);
        installProposalRequest.setSmartContractInputStream(mockstream);

    }

    @Test
    public void testinstallProposalRequestWithMetaInfSetStream() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Error setting chaincode input stream. SmartContract META-INF location  already set. Only one or the other maybe set.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setSmartContractMetaInfLocation(someFileLocation);
        installProposalRequest.setSmartContractInputStream(mockstream);

    }

    @Test
    public void testinstallProposalRequestWithMetaInfSetStreamNULL() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("SmartContract META-INF location may not be null.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setSmartContractMetaInfLocation(null);
    }

    @Test
    public void testinstallProposalRequestWithSourceNull() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("SmartContract source location may not be null");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setSmartContractSourceLocation(null);
    }

    @Test
    public void testinstallProposalRequestWithInputStreamNULL() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("SmartContract input stream may not be null.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setSmartContractInputStream(null);
    }

    @Test
    public void testinstallProposalRequestLocationAndMeta() throws Exception {

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setSmartContractSourceLocation(someFileLocation);
        installProposalRequest.setSmartContractMetaInfLocation(someFileLocation2);

        assertEquals(installProposalRequest.getSmartContractSourceLocation(), someFileLocation);
        assertEquals(installProposalRequest.getSmartContractMetaInfLocation(), someFileLocation2);

    }

}
