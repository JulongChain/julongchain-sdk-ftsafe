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


import org.bcia.javachain.sdk.exception.ProposalException;
import org.bcia.javachain.sdk.transaction.JoinPeerProposalBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;


public class JoinPeerProposalBuilderTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();


    @Test
    public void testBuildNoChaincode() throws Exception {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("No genesis block");

        JoinPeerProposalBuilder builder = JoinPeerProposalBuilder.newBuilder();
        builder.genesisBlock(null);

    }


}
