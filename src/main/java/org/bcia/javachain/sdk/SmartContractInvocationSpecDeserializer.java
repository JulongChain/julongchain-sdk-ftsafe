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

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.bcia.javachain.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.bcia.julongchain.protos.node.SmartContractPackage.SmartContractInvocationSpec;

/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
class SmartContractInvocationSpecDeserializer {
    private final ByteString byteString;
    private WeakReference<SmartContractInvocationSpec> invocationSpec;
    private WeakReference<SmartContractInputDeserializer> chaincodeInputDeserializer;

    SmartContractInvocationSpecDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    SmartContractInvocationSpec getSmartContractInvocationSpec() {
        SmartContractInvocationSpec ret = null;

        if (invocationSpec != null) {
            ret = invocationSpec.get();

        }
        if (ret == null) {

            try {
                ret = SmartContractInvocationSpec.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            invocationSpec = new WeakReference<>(ret);

        }

        return ret;

    }

    SmartContractInputDeserializer getSmartContractInput() {
        SmartContractInputDeserializer ret = null;

        if (chaincodeInputDeserializer != null) {
            ret = chaincodeInputDeserializer.get();

        }
        if (ret == null) {

            ret = new SmartContractInputDeserializer(getSmartContractInvocationSpec().getSmartContractSpec().getInput());

            chaincodeInputDeserializer = new WeakReference<>(ret);

        }

        return ret;

    }
}
