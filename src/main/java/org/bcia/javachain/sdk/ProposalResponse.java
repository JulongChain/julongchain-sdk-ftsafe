/*
 Copyright IBM Corp. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/
package org.bcia.javachain.sdk;

import java.lang.ref.WeakReference;

import javax.xml.bind.DatatypeConverter;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.exception.ProposalException;
import org.bcia.javachain.sdk.helper.Config;
import org.bcia.javachain.sdk.helper.DiagnosticFileDumper;
import org.bcia.julongchain.protos.common.Common;
import org.bcia.julongchain.protos.common.Common.Header;
import org.bcia.julongchain.protos.ledger.rwset.Rwset.TxReadWriteSet;
import org.bcia.julongchain.protos.msp.Identities;
import org.bcia.julongchain.protos.node.ProposalPackage;
import org.bcia.julongchain.protos.node.ProposalPackage.SmartContractHeaderExtension;
import org.bcia.julongchain.protos.node.ProposalResponsePackage;

/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
public class ProposalResponse extends SmartContractResponse {

    private static final Log logger = LogFactory.getLog(ProposalResponse.class);
    private static final Config config = Config.getConfig();
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;

    private boolean isVerified = false;

    private WeakReference<ProposalResponsePayloadDeserializer> proposalResponsePayload;
    private ProposalPackage.Proposal proposal;
    private ProposalResponsePackage.ProposalResponse proposalResponse;
    private Node peer = null;
    private SmartContractID chaincodeID = null;

    ProposalResponse(String transactionID, String chaincodeID, int status, String message) {
        super(transactionID, chaincodeID, status, message);

    }

    ProposalResponsePayloadDeserializer getProposalResponsePayloadDeserializer() throws InvalidArgumentException {
        if (isInvalid()) {
            throw new InvalidArgumentException("Proposal response is invalid.");
        }

        ProposalResponsePayloadDeserializer ret = null;

        if (proposalResponsePayload != null) {
            ret = proposalResponsePayload.get();

        }
        if (ret == null) {

            try {
                ret = new ProposalResponsePayloadDeserializer(proposalResponse.getPayload());
            } catch (Exception e) {
                throw new InvalidArgumentException(e);
            }

            proposalResponsePayload = new WeakReference<>(ret);
        }

        return ret;

    }

    ByteString getPayloadBytes() {
        return proposalResponse.getPayload();

    }

    public boolean isVerified() {
        return isVerified;
    }

    /*
     * Verifies that a Proposal response is properly signed. The payload is the
     * concatenation of the response payload byte string and the endorsement The
     * certificate (public key) is gotten from the Endorsement.Endorser.IdBytes
     * field
     *
     * @param crypto the CryptoPrimitives instance to be used for signing and
     * verification
     *
     * @return true/false depending on result of signature verification
     */
    public boolean verify() {

        if (isVerified()) { // check if this proposalResponse was already verified   by client code
            return isVerified();
        }

        if (isInvalid()) {
            this.isVerified = false;
        }

        ProposalResponsePackage.Endorsement endorsement = this.proposalResponse.getEndorsement();
        ByteString sig = endorsement.getSignature();

        try {
            Identities.SerializedIdentity endorser = Identities.SerializedIdentity
                    .parseFrom(endorsement.getEndorser());
            ByteString plainText = proposalResponse.getPayload().concat(endorsement.getEndorser());

            //TODO 沒搞清楚ｓｅｒｉａｌｉｚｅ和ｓｉｇｎ的區別，先注視掉不驗證
            //this.isVerified = crypto.verify(endorser.getIdBytes().toByteArray(), sig.toByteArray(), plainText.toByteArray());

        } catch (InvalidProtocolBufferException e) {
            logger.error("verify: Cannot retrieve peer identity from ProposalResponse. Error is: " + e.getMessage(), e);
            this.isVerified = false;
        }

        return this.isVerified;
    } // verify

    public ProposalPackage.Proposal getProposal() {
        return proposal;
    }

    public void setProposal(ProposalPackage.SignedProposal signedProposal) throws ProposalException {

        try {
            this.proposal = ProposalPackage.Proposal.parseFrom(signedProposal.getProposalBytes());
        } catch (InvalidProtocolBufferException e) {
            throw new ProposalException("Proposal exception", e);

        }
    }

    /**
     * Get response to the proposal returned by the peer.
     *
     * @return peer response.
     */

    public ProposalResponsePackage.ProposalResponse getProposalResponse() {
        return proposalResponse;
    }

    public void setProposalResponse(ProposalResponsePackage.ProposalResponse proposalResponse) {
        this.proposalResponse = proposalResponse;
    }

    /**
     * The peer this proposal was created on.
     *
     * @return See {@link Node}
     */

    public Node getNode() {
        return this.peer;
    }

    void setNode(Node peer) {
        this.peer = peer;
    }

//    public ByteString getPayload() {
//        return proposalResponse.getPayload();
//    }

    /**
     * SmartContract ID that was executed.
     *
     * @return See {@link SmartContractID}
     * @throws InvalidArgumentException
     */

    public SmartContractID getSmartContractID() throws InvalidArgumentException {

        try {

            if (chaincodeID == null) {

                Header header = Header.parseFrom(proposal.getHeader());
                Common.GroupHeader channelHeader = Common.GroupHeader.parseFrom(header.getGroupHeader());
                SmartContractHeaderExtension chaincodeHeaderExtension = SmartContractHeaderExtension.parseFrom(channelHeader.getExtension());
                chaincodeID = new SmartContractID(chaincodeHeaderExtension.getSmartContractId());
            }
            return chaincodeID;

        } catch (Exception e) {
            throw new InvalidArgumentException(e);
        }

    }

    /**
     * SmartContractActionResponsePayload is the result of the executing chaincode.
     *
     * @return the result of the executing chaincode.
     * @throws InvalidArgumentException
     */

    public byte[] getSmartContractActionResponsePayload() throws InvalidArgumentException {

        if (isInvalid()) {
            throw new InvalidArgumentException("Proposal response is invalid.");
        }

        try {

            final ProposalResponsePayloadDeserializer proposalResponsePayloadDeserializer = getProposalResponsePayloadDeserializer();
            ByteString ret = proposalResponsePayloadDeserializer.getExtension().getSmartContractAction().getResponse().getPayload();
            if (null == ret) {
                return null;
            }
            return ret.toByteArray();
        } catch (InvalidArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidArgumentException(e);
        }
    }

    /**
     * getSmartContractActionResponseStatus returns the what chaincode executions set as the return status.
     *
     * @return status code.
     * @throws InvalidArgumentException
     */

    public int getSmartContractActionResponseStatus() throws InvalidArgumentException {
        if (isInvalid()) {
            throw new InvalidArgumentException("Proposal response is invalid.");
        }

        try {

            final ProposalResponsePayloadDeserializer proposalResponsePayloadDeserializer = getProposalResponsePayloadDeserializer();
            return proposalResponsePayloadDeserializer.getExtension().getResponseStatus();

        } catch (InvalidArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidArgumentException(e);
        }

    }

    /**
     * getSmartContractActionResponseReadWriteSetInfo get this proposals read write set.
     *
     * @return The read write set. See {@link TxReadWriteSetInfo}
     * @throws InvalidArgumentException
     */

    public TxReadWriteSetInfo getSmartContractActionResponseReadWriteSetInfo() throws InvalidArgumentException {

        if (isInvalid()) {
            throw new InvalidArgumentException("Proposal response is invalid.");
        }

        try {

            final ProposalResponsePayloadDeserializer proposalResponsePayloadDeserializer = getProposalResponsePayloadDeserializer();

            TxReadWriteSet txReadWriteSet = proposalResponsePayloadDeserializer.getExtension().getResults();

            if (txReadWriteSet == null) {
                return null;
            }

            return new TxReadWriteSetInfo(txReadWriteSet);

        } catch (Exception e) {
            throw new InvalidArgumentException(e);
        }

    }

    @Override
    public String toString() {
        return "ProposalResponse{" +
                "isVerified=" + isVerified +
                ", proposalResponsePayload=" + proposalResponsePayload +
                ", proposal=" +"太多..." + //proposal +
                ", proposalResponse=" + proposalResponse +
                ", peer=" + peer +
                ", chaincodeID=" + chaincodeID +
                '}';
    }
}
