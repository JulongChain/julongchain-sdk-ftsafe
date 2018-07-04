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
import com.google.protobuf.Timestamp;

import org.bcia.javachain.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.bcia.javachain.protos.common.Common.GroupHeader;

/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
class GroupHeaderDeserializer {
    private final ByteString byteString;
    private WeakReference<GroupHeader> channelHeader;

    GroupHeaderDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    GroupHeader getGroupHeader() {
        GroupHeader ret = null;

        if (channelHeader != null) {
            ret = channelHeader.get();

        }
        if (null == ret) {
            try {
                ret = GroupHeader.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }
            channelHeader = new WeakReference<>(ret);

        }

        return ret;

    }

    String getGroupId() {
        return getGroupHeader().getGroupId();
    }

    long getEpoch() {
        return getGroupHeader().getEpoch();
    }

    Timestamp getTimestamp() {
        return getGroupHeader().getTimestamp();
    }

    String getTxId() {
        return getGroupHeader().getTxId();
    }

    int getType() {
        return getGroupHeader().getType();
    }

    int getVersion() {
        return getGroupHeader().getVersion();
    }
}
