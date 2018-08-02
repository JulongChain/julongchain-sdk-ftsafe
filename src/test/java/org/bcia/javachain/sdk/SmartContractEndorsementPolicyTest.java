/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import org.apache.commons.compress.utils.IOUtils;
import org.bcia.julongchain.protos.common.MspPrincipal;
import org.bcia.julongchain.protos.common.MspPrincipal.MSPPrincipal;
import org.bcia.julongchain.protos.common.Policies;
import org.bcia.julongchain.protos.common.Policies.SignaturePolicy.TypeCase;
import org.bcia.julongchain.protos.common.Policies.SignaturePolicyEnvelope;
import org.bcia.javachain.sdk.SmartContractEndorsementPolicy;
import org.bcia.javachain.sdk.exception.SmartContractEndorsementPolicyParseException;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.*;

public class SmartContractEndorsementPolicyTest {

    /**
     * Test method for {@link org.bcia.javachain.sdk.SmartContractEndorsementPolicy#SmartContractEndorsementPolicy()}.
     */
    @Test
    public void testPolicyCtor() {
        SmartContractEndorsementPolicy nullPolicy = new SmartContractEndorsementPolicy();
        assertNull(nullPolicy.getSmartContractEndorsementPolicyAsBytes());
    }

    /**
     * Test method for {@link org.bcia.javachain.sdk.SmartContractEndorsementPolicy#fromFile(File)} (java.io.File)}.
     *
     * @throws IOException
     */
    @Test(expected = IOException.class)
    public void testPolicyCtorFile() throws IOException {
        SmartContractEndorsementPolicy policy = new SmartContractEndorsementPolicy();
        policy.fromFile(new File("/does/not/exists"));
    }

    /**
     * Test method for {@link org.bcia.javachain.sdk.SmartContractEndorsementPolicy#fromFile(File)} (java.io.File)}.
     *
     * @throws IOException
     */
    @Test
    public void testPolicyCtorValidFile() throws IOException {
        URL url = this.getClass().getResource("/policyBitsAdmin");
        File policyFile = new File(url.getFile());
        SmartContractEndorsementPolicy policy = new SmartContractEndorsementPolicy();
        policy.fromFile(policyFile);
        InputStream policyStream = this.getClass().getResourceAsStream("/policyBitsAdmin");
        byte[] policyBits = IOUtils.toByteArray(policyStream);
        assertArrayEquals(policyBits, policy.getSmartContractEndorsementPolicyAsBytes());
    }

    /**
     * Test method for {@link org.bcia.javachain.sdk.SmartContractEndorsementPolicy#fromBytes(byte[])}.
     */
    @Test
    public void testPolicyCtorByteArray() {
        byte[] testInput = "this is a test".getBytes(UTF_8);
        SmartContractEndorsementPolicy fakePolicy = new SmartContractEndorsementPolicy();
        fakePolicy.fromBytes(testInput);

        assertEquals(fakePolicy.getSmartContractEndorsementPolicyAsBytes(), testInput);
    }

    /**
     * Test method for {@link SmartContractEndorsementPolicy#fromYamlFile(File)}
     * @throws IOException
     * @throws SmartContractEndorsementPolicyParseException
     */
    @Test
    public void testSDKIntegrationYaml() throws IOException, SmartContractEndorsementPolicyParseException {

        SmartContractEndorsementPolicy itTestPolicy = new SmartContractEndorsementPolicy();
        itTestPolicy.fromYamlFile(new File("src/test/fixture/sdkintegration/chaincodeendorsementpolicy.yaml"));

        SignaturePolicyEnvelope sigPolEnv = SignaturePolicyEnvelope.parseFrom(itTestPolicy.getSmartContractEndorsementPolicyAsBytes());
        List<MSPPrincipal> identitiesList = sigPolEnv.getIdentitiesList();
        for (MSPPrincipal ident : identitiesList) {

            MSPPrincipal mspPrincipal = MSPPrincipal.parseFrom(ident.getPrincipal());
            MSPPrincipal.Classification principalClassification = mspPrincipal.getPrincipalClassification();
            assertEquals(principalClassification.toString(), MSPPrincipal.Classification.ROLE.name());
            MspPrincipal.MSPRole mspRole = MspPrincipal.MSPRole.parseFrom(ident.getPrincipal());

            String iden = mspRole.getMspIdentifier();
            assertTrue("Org1MSP".equals(iden) || "Org2MSP".equals(iden));
            assertTrue(mspRole.getRole().getNumber() == MspPrincipal.MSPRole.MSPRoleType.ADMIN_VALUE
                    || mspRole.getRole().getNumber() == MspPrincipal.MSPRole.MSPRoleType.MEMBER_VALUE);

        }

        Policies.SignaturePolicy rule = sigPolEnv.getRule();
        TypeCase typeCase = rule.getTypeCase();
        assertEquals(TypeCase.N_OUT_OF.getNumber(), typeCase.getNumber());
    }

    @Test
    public void testBadYaml() throws IOException, SmartContractEndorsementPolicyParseException {

        try {
            SmartContractEndorsementPolicy itTestPolicy = new SmartContractEndorsementPolicy();
            itTestPolicy.fromYamlFile(new File("src/test/fixture/sample_chaincode_endorsement_policies/badusertestCCEPPolicy.yaml"));

            fail("Expected SmartContractEndorsementPolicyParseException");

        } catch (SmartContractEndorsementPolicyParseException e) {

        } catch (Exception e) {

            fail("Expected SmartContractEndorsementPolicyParseException");
        }

    }

    //src/test/fixture/sample_chaincode_endorsement_policies/badusertestCCEPPolicy.yaml

//    /**
//     * Test method for {@link org.bcia.javachain.sdk.SmartContractEndorsementPolicy#fromBytes(byte[])}.
//     */
//    @Test
//    public void testSetPolicy() {
//        byte[] testInput = "this is a test".getBytes(UTF_8);
//        SmartContractEndorsementPolicy fakePolicy = new SmartContractEndorsementPolicy() ;
//        fakePolicy.fromBytes(testInput);
//        assertEquals(fakePolicy.getSmartContractEndorsementPolicyAsBytes(), testInput);
//    }

}
