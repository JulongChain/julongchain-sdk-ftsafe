/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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
package org.bcia.javachain.sdk.transaction;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.bcia.javachain.sdk.helper.Utils.logString;
import static org.bcia.javachain.sdk.helper.Utils.toHexString;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bcia.julongchain.protos.common.Common;
import org.bcia.julongchain.protos.common.Common.Envelope;
import org.bcia.julongchain.protos.common.Common.GroupHeader;
import org.bcia.julongchain.protos.common.Common.HeaderType;
import org.bcia.julongchain.protos.common.Common.Payload;
import org.bcia.julongchain.protos.common.Common.SignatureHeader;
import org.bcia.julongchain.protos.consenter.Ab.SeekInfo;
import org.bcia.julongchain.protos.consenter.Ab.SeekInfo.SeekBehavior;
import org.bcia.julongchain.protos.consenter.Ab.SeekPosition;
import org.bcia.julongchain.protos.msp.Identities;
import org.bcia.julongchain.protos.node.ProposalPackage.SmartContractHeaderExtension;
import org.bcia.julongchain.protos.node.SmartContractPackage;
import org.bcia.julongchain.protos.node.SmartContractPackage.SmartContractDeploymentSpec;
import org.bcia.julongchain.protos.node.SmartContractPackage.SmartContractInput;
import org.bcia.julongchain.protos.node.SmartContractPackage.SmartContractSpec;
import org.bcia.julongchain.protos.node.SmartContractPackage.SmartContractSpec.Type;
import org.bcia.javachain.sdk.User;
import org.bcia.javachain.sdk.exception.CryptoException;
import org.bcia.javachain.sdk.security.CryptoPrimitives;
import org.bcia.javachain.sdk.security.CryptoSuite;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;

/**
 * Internal use only, not a public API.
 * 
 * modified for Node,SmartContractPackage,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
public final class ProtoUtils {

    private static final Log logger = LogFactory.getLog(ProtoUtils.class);
    private static final boolean isDebugLevel = logger.isDebugEnabled();
    public static CryptoSuite suite;

    /**
     * Private constructor to prevent instantiation.
     */
    private ProtoUtils() {
    }

    // static CryptoSuite suite = null;

    /*
     * createGroupHeader create chainHeader
     *
     * @param type                     header type. See {@link GroupHeader.Builder#setType}.
     * @param txID                     transaction ID. See {@link GroupHeader.Builder#setTxId}.
     * @param channelID                channel ID. See {@link GroupHeader.Builder#setGroupId}.
     * @param epoch                    the epoch in which this header was generated. See {@link GroupHeader.Builder#setEpoch}.
     * @param timeStamp                local time when the message was created. See {@link GroupHeader.Builder#setTimestamp}.
     * @param chaincodeHeaderExtension extension to attach dependent on the header type. See {@link GroupHeader.Builder#setExtension}.
     * @param tlsCertHash
     * @return a new chain header.
     */
    public static GroupHeader createGroupHeader(HeaderType type, String txID, String channelID, long epoch,
                                                    Timestamp timeStamp, SmartContractHeaderExtension chaincodeHeaderExtension,
                                                    byte[] tlsCertHash) {

        if (isDebugLevel) {
            String tlschs = "";
            if (tlsCertHash != null) {
                tlschs = DatatypeConverter.printHexBinary(tlsCertHash);

            }
            logger.debug(format("GroupHeader: type: %s, version: 1, Txid: %s, channelId: %s, epoch %d, clientTLSCertificate digest: %s",
                    type.name(), txID, channelID, epoch, tlschs));

        }

        GroupHeader.Builder ret = GroupHeader.newBuilder()
                .setType(type.getNumber())
                .setVersion(1)
                .setTxId(txID)
                .setGroupId(channelID)
                .setTimestamp(timeStamp)
                .setEpoch(epoch);
        if (null != chaincodeHeaderExtension) {
            ret.setExtension(chaincodeHeaderExtension.toByteString());
        }

        if (tlsCertHash != null) {
            ret.setTlsCertHash(ByteString.copyFrom(tlsCertHash));
        }

        return ret.build();

    }

    public static SmartContractDeploymentSpec createDeploymentSpec(Type ccType, String name, String chaincodePath,
                                                               String chaincodeVersion, List<String> args,
                                                               byte[] codePackage) {

    	SmartContractPackage.SmartContractID.Builder chaincodeIDBuilder = SmartContractPackage.SmartContractID.newBuilder().setName(name).setVersion(chaincodeVersion);
        if (chaincodePath != null) {
            chaincodeIDBuilder = chaincodeIDBuilder.setPath(chaincodePath);
        }

        SmartContractPackage.SmartContractID chaincodeID = chaincodeIDBuilder.build();

        // build chaincodeInput
        List<ByteString> argList = new ArrayList<>(args == null ? 0 : args.size());
        if (args != null && args.size() != 0) {

            for (String arg : args) {
                argList.add(ByteString.copyFrom(arg.getBytes(UTF_8)));
            }

        }

        SmartContractInput chaincodeInput = SmartContractInput.newBuilder().addAllArgs(argList).build();

        // Construct the SmartContractSpec
        SmartContractSpec chaincodeSpec = SmartContractSpec.newBuilder().setType(ccType).setSmartContractId(chaincodeID)
                .setInput(chaincodeInput)
                .build();

        if (isDebugLevel) {
            StringBuilder sb = new StringBuilder(1000);
            sb.append("SmartContractDeploymentSpec chaincode cctype: ")
                    .append(ccType.name())
                    .append(", name:")
                    .append(chaincodeID.getName())
                    .append(", path: ")
                    .append(chaincodeID.getPath())
                    .append(", version: ")
                    .append(chaincodeID.getVersion());

            String sep = "";
            sb.append(" args(");

            for (ByteString x : argList) {
                sb.append(sep).append("\"").append(logString(new String(x.toByteArray(), UTF_8))).append("\"");
                sep = ", ";

            }
            sb.append(")");

            logger.debug(sb.toString());

        }

        SmartContractDeploymentSpec.Builder chaincodeDeploymentSpecBuilder = SmartContractDeploymentSpec
                .newBuilder().setSmartContractSpec(chaincodeSpec) //.setEffectiveDate(context.getFabricTimestamp())
                .setExecEnv(SmartContractDeploymentSpec.ExecutionEnvironment.DOCKER);

        if (codePackage != null) {
            chaincodeDeploymentSpecBuilder.setCodePackage(ByteString.copyFrom(codePackage));

        }

        return chaincodeDeploymentSpecBuilder.build();

    }

    public static ByteString getSignatureHeaderAsByteString(TransactionContext transactionContext) {

        return getSignatureHeaderAsByteString(transactionContext.getUser(), transactionContext);
    }

    public static ByteString getSignatureHeaderAsByteString(User user, TransactionContext transactionContext) {

        final Identities.SerializedIdentity identity = ProtoUtils.createSerializedIdentity(user);

        if (isDebugLevel) {

            String cert = user.getEnrollment().getCert();
            // logger.debug(format(" User: %s Certificate:\n%s", user.getName(), cert));

            if (null == suite) {

                try {
                    suite = CryptoSuite.Factory.getCryptoSuite();
                } catch (Exception e) {
                    //best try.
                }

            }
            if (null != suite && suite instanceof CryptoPrimitives) {

                CryptoPrimitives cp = (CryptoPrimitives) suite;
                byte[] der = cp.certificateToDER(cert);
                if (null != der && der.length > 0) {

                    cert = toHexString(suite.hash(der));

                }

            }

            logger.debug(format("SignatureHeader: nonce: %s, User:%s, MSPID: %s, idBytes: %s",
                    toHexString(transactionContext.getNonce()),
                    user.getName(),
                    identity.getMspid(),
                    cert
            ));

        }
        return SignatureHeader.newBuilder()
                .setCreator(identity.toByteString())
                .setNonce(transactionContext.getNonce())
                .build().toByteString();
    }

    public static Identities.SerializedIdentity createSerializedIdentity(User user) {

        return Identities.SerializedIdentity.newBuilder()
                .setIdBytes(ByteString.copyFromUtf8(user.getEnrollment().getCert()))
                .setMspid(user.getMspId()).build();
    }

    public static Timestamp getCurrentFabricTimestamp() {
        Instant time = Instant.now();
        return Timestamp.newBuilder().setSeconds(time.getEpochSecond())
                .setNanos(time.getNano()).build();
    }

    public static Date getDateFromTimestamp(Timestamp timestamp) {
        return new Date(Timestamps.toMillis(timestamp));
    }

    static Timestamp getTimestampFromDate(Date date) {

        long millis = date.getTime();
        return Timestamp.newBuilder().setSeconds(millis / 1000)
                .setNanos((int) ((millis % 1000) * 1000000)).build();
    }

    public static Envelope createSeekInfoEnvelope(TransactionContext transactionContext, SeekInfo seekInfo, byte[] tlsCertHash) throws CryptoException {

        GroupHeader seekInfoHeader = createGroupHeader(Common.HeaderType.DELIVER_SEEK_INFO,
                transactionContext.getTxID(), transactionContext.getGroupID(), transactionContext.getEpoch(),
                transactionContext.getFabricTimestamp(), null, tlsCertHash);

        SignatureHeader signatureHeader = SignatureHeader.newBuilder()
                .setCreator(transactionContext.getIdentity().toByteString())
                .setNonce(transactionContext.getNonce())
                .build();

        Common.Header seekHeader = Common.Header.newBuilder()
                .setSignatureHeader(signatureHeader.toByteString())
                .setGroupHeader(seekInfoHeader.toByteString())
                .build();

        Payload seekPayload = Payload.newBuilder()
                .setHeader(seekHeader)
                .setData(seekInfo.toByteString())
                .build();

        return Envelope.newBuilder().setSignature(transactionContext.signByteString(seekPayload.toByteArray()))
                .setPayload(seekPayload.toByteString())
                .build();

    }

    public static Envelope createSeekInfoEnvelope(TransactionContext transactionContext, SeekPosition startPosition,
                                                  SeekPosition stopPosition,
                                                  SeekBehavior seekBehavior, byte[] tlsCertHash) throws CryptoException {

        return createSeekInfoEnvelope(transactionContext, SeekInfo.newBuilder()
                .setStart(startPosition)
                .setStop(stopPosition)
                .setBehavior(seekBehavior)
                .build(), tlsCertHash);

    }
}
