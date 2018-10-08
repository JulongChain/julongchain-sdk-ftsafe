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
import org.bcia.julongchain.protos.node.SmartContractEventPackage;

/**
 * Encapsulates a SmartContract event.
 * 
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
public class SmartContractEvent {
    private final ByteString byteString;
    private WeakReference<SmartContractEventPackage.SmartContractEvent> chaincodeEvent;

    SmartContractEvent(ByteString byteString) {
        this.byteString = byteString;
    }

    SmartContractEventPackage.SmartContractEvent getSmartContractEvent() {
        SmartContractEventPackage.SmartContractEvent ret = null;

        if (chaincodeEvent != null) {
            ret = chaincodeEvent.get();

        }
        if (ret == null) {

            try {
                ret = SmartContractEventPackage.SmartContractEvent.parseFrom(byteString);

            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            chaincodeEvent = new WeakReference<>(ret);

        }

        return ret;

    }

    /**
     * Get SmartContract event's name;
     *
     * @return Return name;
     */
    public String getEventName() {

        return getSmartContractEvent().getEventName();

    }

    /**
     * Get SmartContract identifier.
     *
     * @return The identifier
     */
    public String getSmartContractId() {

        return getSmartContractEvent().getSmartContractId();

    }

    /**
     * Get transaction id associated with this event.
     *
     * @return The transactions id.
     */
    public String getTxId() {

        return getSmartContractEvent().getTxId();

    }

    /**
     * Binary data associated with this event.
     *
     * @return binary data set by the chaincode for this event. This may return null.
     */
    public byte[] getPayload() {

        ByteString ret = getSmartContractEvent().getPayload();
        if (null == ret) {
            return null;
        }

        return ret.toByteArray();

    }

}
