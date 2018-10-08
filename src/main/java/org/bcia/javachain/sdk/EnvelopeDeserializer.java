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
import org.bcia.julongchain.protos.common.Common.GroupHeader;
import org.bcia.julongchain.protos.common.Common.Envelope;
import org.bcia.julongchain.protos.common.Common.Payload;
import org.bcia.julongchain.protos.node.TransactionPackage;

/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
class EnvelopeDeserializer {
    protected final ByteString byteString;
    private final byte validcode;
    private WeakReference<Envelope> envelope;
    private WeakReference<PayloadDeserializer> payload;

    EnvelopeDeserializer(ByteString byteString, byte validcode) {
        this.byteString = byteString;

        this.validcode = validcode;
    }

    Envelope getEnvelope() {
        Envelope ret = null;

        if (envelope != null) {
            ret = envelope.get();

        }
        if (ret == null) {

            try {
                ret = Envelope.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            envelope = new WeakReference<>(ret);

        }

        return ret;

    }

    byte[] getSignature() {

        return getEnvelope().getSignature().toByteArray();

    }

    PayloadDeserializer getPayload() {

        PayloadDeserializer ret = null;

        if (payload != null) {
            ret = payload.get();

        }
        if (ret == null) {

            ret = new PayloadDeserializer(getEnvelope().getPayload());
            payload = new WeakReference<>(ret);

        }

        return ret;
    }

    private Integer type = null;

    int getType() {
        if (type == null) {

            type = getPayload().getHeader().getGroupHeader().getType();

        }
        return type;
    }

    /**
     * @return whether this Transaction is marked as TxValidationCode.VALID
     */
    public boolean isValid() {

        return validcode == TransactionPackage.TxValidationCode.VALID_VALUE;
    }

    /**
     * @return the validation code of this Transaction (enumeration TxValidationCode in Transaction.proto)
     */
    public byte validationCode() {

        return validcode;
    }

    static EnvelopeDeserializer newInstance(ByteString byteString, byte b) throws InvalidProtocolBufferException {

        EnvelopeDeserializer ret;

        final int type = GroupHeader.parseFrom(Payload.parseFrom(Envelope.parseFrom(byteString).getPayload())
                .getHeader().getGroupHeader()).getType();

       /*

    MESSAGE = 0;                   // Used for messages which are signed but opaque
    CONFIG = 1;                    // Used for messages which express the channel config
    CONFIG_UPDATE = 2;             // Used for transactions which update the channel config
    ENDORSER_TRANSACTION = 3;      // Used by the SDK to submit endorser based transactions
    ORDERER_TRANSACTION = 4;       // Used internally by the orderer for management
    DELIVER_SEEK_INFO = 5;         // Used as the type for Envelope messages submitted to instruct the Deliver API to seek
    CHAINCODE_PACKAGE = 6;         // Used for packaging chaincode artifacts for install

     */

        switch (type) {
            case 3:
                ret = new EndorserTransactionEnvDeserializer(byteString, b);
                break;
            default: //just assume base properties.
                ret = new EnvelopeDeserializer(byteString, b);
                break;
        }
        return ret;

    }

}
