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

import org.bcia.javachain.protos.node.SmartContract;

/**
 * Request for getting information about the blockchain ledger.
 * 
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
public class QuerySCCRequest extends TransactionRequest {

    public static final String GETCHAININFO = "GetChainInfo";
    public static final String GETBLOCKBYNUMBER = "GetBlockByNumber";
    public static final String GETBLOCKBYHASH = "GetBlockByHash";
    public static final String GETTRANSACTIONBYID = "GetTransactionByID";
    public static final String GETBLOCKBYTXID = "GetBlockByTxID";

    public QuerySCCRequest(User userContext) {
        super(userContext);
    }

    @Override
    public SmartContractID getSmartContractID() {
        return new SmartContractID(
                SmartContract.SmartContractID.newBuilder().setName("qscc").build());
    }

}
