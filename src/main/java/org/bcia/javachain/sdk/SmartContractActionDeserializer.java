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
import org.bcia.julongchain.protos.ledger.rwset.Rwset.TxReadWriteSet;

import static org.bcia.julongchain.protos.node.ProposalPackage.SmartContractAction;

/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
class SmartContractActionDeserializer {
    private final ByteString byteString;
    private WeakReference<SmartContractAction> chaincodeAction;

    SmartContractActionDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    SmartContractAction getSmartContractAction() {
        SmartContractAction ret = null;

        if (chaincodeAction != null) {
            ret = chaincodeAction.get();

        }
        if (ret == null) {

            try {
                ret = SmartContractAction.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            chaincodeAction = new WeakReference<>(ret);

        }

        return ret;

    }

    SmartContractEvent getEvent() {

        SmartContractAction ca = getSmartContractAction();
        ByteString eventsBytes = ca.getEvents();
        if (eventsBytes == null || eventsBytes.isEmpty()) {
            return null;
        }

        return new SmartContractEvent(eventsBytes);

    }

    TxReadWriteSet getResults() {

        try {
            return TxReadWriteSet.parseFrom(getSmartContractAction().getResults());
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidProtocolBufferRuntimeException(e);
        }

    }

    String getResponseMessage() {
        return getSmartContractAction().getResponse().getMessage();

    }

    byte[] getResponseMessageBytes() {
        return getSmartContractAction().getResponse().getMessageBytes().toByteArray();

    }

    int getResponseStatus() {
        return getSmartContractAction().getResponse().getStatus();

    }

    ByteString getResponsePayload() {
        return getSmartContractAction().getResponse().getPayload();

    }

}
