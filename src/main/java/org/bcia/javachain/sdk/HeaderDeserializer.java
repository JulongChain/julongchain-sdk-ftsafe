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

import com.google.protobuf.InvalidProtocolBufferException;

import org.bcia.javachain.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.bcia.julongchain.protos.common.Common;
import org.bcia.julongchain.protos.common.Common.Header;
import org.bcia.julongchain.protos.msp.Identities;


/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
class HeaderDeserializer {

    private final Header header;
    private WeakReference<GroupHeaderDeserializer> channelHeader;

    HeaderDeserializer(Header header) {
        this.header = header;
    }

    Header getHeader() {

        return header;
    }

    GroupHeaderDeserializer getGroupHeader() {

        GroupHeaderDeserializer ret = null;

        if (channelHeader != null) {
            ret = channelHeader.get();

        }
        if (ret == null) {

            ret = new GroupHeaderDeserializer(getHeader().getGroupHeader());
            channelHeader = new WeakReference<>(ret);

        }

        return ret;

    }

    Identities.SerializedIdentity getCreator() {

        try {
            Common.SignatureHeader signatureHeader1 = Common.SignatureHeader.parseFrom(header.getSignatureHeader());
            return Identities.SerializedIdentity.parseFrom(signatureHeader1.getCreator());
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidProtocolBufferRuntimeException(e);
        }

    }

    byte[] getNonce() {

        try {
            Common.SignatureHeader signatureHeader1 = Common.SignatureHeader.parseFrom(header.getSignatureHeader());
            return signatureHeader1.getNonce().toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidProtocolBufferRuntimeException(e);
        }

    }
}
