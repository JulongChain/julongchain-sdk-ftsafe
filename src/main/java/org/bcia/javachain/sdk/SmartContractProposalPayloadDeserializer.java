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

import java.lang.ref.WeakReference;

import org.bcia.javachain.sdk.exception.InvalidProtocolBufferRuntimeException;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import static org.bcia.julongchain.protos.node.ProposalPackage.SmartContractProposalPayload;

/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
class SmartContractProposalPayloadDeserializer {
    private final ByteString byteString;
    private WeakReference<SmartContractProposalPayload> chaincodeProposalPayload;
    private WeakReference<SmartContractInvocationSpecDeserializer> invocationSpecDeserializer;

    SmartContractProposalPayloadDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    SmartContractProposalPayload getSmartContractProposalPayload() {
        SmartContractProposalPayload ret = null;

        if (chaincodeProposalPayload != null) {
            ret = chaincodeProposalPayload.get();

        }
        if (ret == null) {

            try {
                ret = SmartContractProposalPayload.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            chaincodeProposalPayload = new WeakReference<>(ret);

        }

        return ret;

    }

    SmartContractInvocationSpecDeserializer getSmartContractInvocationSpec() {
        SmartContractInvocationSpecDeserializer ret = null;

        if (invocationSpecDeserializer != null) {
            ret = invocationSpecDeserializer.get();

        }
        if (ret == null) {

            ret = new SmartContractInvocationSpecDeserializer(getSmartContractProposalPayload().getInput());

            invocationSpecDeserializer = new WeakReference<>(ret);

        }

        return ret;

    }

}
