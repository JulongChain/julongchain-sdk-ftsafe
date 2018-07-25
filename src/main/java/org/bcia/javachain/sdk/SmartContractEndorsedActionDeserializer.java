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
import java.util.List;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.bcia.javachain.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.bcia.julongchain.protos.node.ProposalResponsePackage;

import static org.bcia.julongchain.protos.node.TransactionPackage.SmartContractEndorsedAction;

/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
class SmartContractEndorsedActionDeserializer {
    private final ByteString byteString;
    private WeakReference<SmartContractEndorsedAction> chaincodeEndorsedAction;
    private WeakReference<ProposalResponsePayloadDeserializer> proposalResponsePayload;

    SmartContractEndorsedActionDeserializer(SmartContractEndorsedAction action) {
        byteString = action.toByteString();
        chaincodeEndorsedAction = new WeakReference<>(action);

    }

    SmartContractEndorsedAction getSmartContractEndorsedAction() {
        SmartContractEndorsedAction ret = null;

        if (chaincodeEndorsedAction != null) {
            ret = chaincodeEndorsedAction.get();

        }
        if (ret == null) {

            try {
                ret = SmartContractEndorsedAction.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            chaincodeEndorsedAction = new WeakReference<>(ret);
        }

        return ret;

    }

    int getEndorsementsCount() {

        return getSmartContractEndorsedAction().getEndorsementsCount();

    }

    List<ProposalResponsePackage.Endorsement> getEndorsements() {

        return getSmartContractEndorsedAction().getEndorsementsList();
    }

    byte[] getEndorsementSignature(int index) {

        return getSmartContractEndorsedAction().getEndorsements(index).getSignature().toByteArray();
    }

    ProposalResponsePayloadDeserializer getProposalResponsePayload() {

        ProposalResponsePayloadDeserializer ret = null;

        if (proposalResponsePayload != null) {
            ret = proposalResponsePayload.get();

        }
        if (ret == null) {

            ret = new ProposalResponsePayloadDeserializer(getSmartContractEndorsedAction().getProposalResponsePayload());
            proposalResponsePayload = new WeakReference<>(ret);

        }

        return ret;

    }

}
