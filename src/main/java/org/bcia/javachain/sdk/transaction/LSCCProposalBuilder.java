/*
 *  Copyright 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import org.bcia.javachain.protos.node.ProposalPackage;
import org.bcia.javachain.protos.node.SmartContractPackage;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.exception.ProposalException;

/**
 * modified for Node,SmartContractPackage,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
public class LSCCProposalBuilder extends ProposalBuilder {
    private static final String LSCC_CHAIN_NAME = "lscc";
    private static final SmartContractPackage.SmartContractID CHAINCODE_ID_LSCC =
            SmartContractPackage.SmartContractID.newBuilder().setName(LSCC_CHAIN_NAME).build();

    @Override
    public LSCCProposalBuilder context(TransactionContext context) {
        super.context(context);
        return this;
    }

    @Override
    public ProposalPackage.Proposal build() throws ProposalException, InvalidArgumentException {

        smartContractID(CHAINCODE_ID_LSCC);

        return super.build();

    }
}
