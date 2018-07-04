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
import org.bcia.javachain.protos.node.TransactionPackage.SmartContractActionPayload;

/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
class SmartContractActionPayloadDeserializer {
    private final ByteString byteString;
    private WeakReference<SmartContractActionPayload> chaincodeActionPayload;
    private WeakReference<SmartContractEndorsedActionDeserializer> chaincodeEndorsedActionDeserializer;
    private WeakReference<SmartContractProposalPayloadDeserializer> chaincodeProposalPayloadDeserializer;

    SmartContractActionPayloadDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    SmartContractActionPayload getSmartContractActionPayload() {
        SmartContractActionPayload ret = null;

        if (chaincodeActionPayload != null) {
            ret = chaincodeActionPayload.get();

        }
        if (ret == null) {

            try {
                ret = SmartContractActionPayload.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            chaincodeActionPayload = new WeakReference<>(ret);

        }

        return ret;

    }

    SmartContractEndorsedActionDeserializer getAction() {
        SmartContractEndorsedActionDeserializer ret = null;

        if (chaincodeEndorsedActionDeserializer != null) {
            ret = chaincodeEndorsedActionDeserializer.get();

        }
        if (ret == null) {

            ret = new SmartContractEndorsedActionDeserializer(getSmartContractActionPayload().getAction());

            chaincodeEndorsedActionDeserializer = new WeakReference<>(ret);

        }

        return ret;

    }

    SmartContractProposalPayloadDeserializer getSmartContractProposalPayload() {

        SmartContractProposalPayloadDeserializer ret = null;

        if (chaincodeProposalPayloadDeserializer != null) {
            ret = chaincodeProposalPayloadDeserializer.get();

        }
        if (ret == null) {

            ret = new SmartContractProposalPayloadDeserializer(getSmartContractActionPayload().getSmartContractProposalPayload());

            chaincodeProposalPayloadDeserializer = new WeakReference<>(ret);

        }

        return ret;

    }

}
