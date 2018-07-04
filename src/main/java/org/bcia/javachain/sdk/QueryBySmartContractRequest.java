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

import java.util.Map;

import org.bcia.javachain.sdk.exception.InvalidArgumentException;

/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
public class QueryBySmartContractRequest extends TransactionRequest {
    private QueryBySmartContractRequest(User userContext) {
        super(userContext);
    }

    public static QueryBySmartContractRequest newInstance(User userContext) {
        return new QueryBySmartContractRequest(userContext);
    }

    /**
     * Transient data added to the proposal that is not added to the ledger.
     *
     * @param transientMap Map of strings to bytes that's added to the proposal
     * @throws InvalidArgumentException if the argument is null.
     */
    public void setTransientMap(Map<String, byte[]> transientMap) throws InvalidArgumentException {
        if (null == transientMap) {

            throw new InvalidArgumentException("Transient map may not be set to null");

        }
        this.transientMap = transientMap;
    }
}
