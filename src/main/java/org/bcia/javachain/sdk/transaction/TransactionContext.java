/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.bcia.javachain.sdk.transaction;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;

import org.bcia.javachain.common.exception.JavaChainException;
import org.bcia.javachain.common.localmsp.ILocalSigner;
import org.bcia.javachain.common.localmsp.impl.LocalSigner;
import org.bcia.javachain.sdk.Group;
import org.bcia.javachain.sdk.User;
import org.bcia.javachain.sdk.exception.CryptoException;
import org.bcia.javachain.sdk.exception.TransactionException;
import org.bcia.javachain.sdk.helper.Config;
import org.bcia.javachain.sdk.helper.MspStore;
import org.bcia.javachain.sdk.helper.Utils;
import org.bcia.javachain.sdk.security.CryptoSuite;
import org.bcia.javachain.sdk.security.msp.mgmt.Identity;
import org.bcia.julongchain.protos.msp.Identities;

/**
 * Internal class, not an public API.
 * A transaction context emits events 'submitted', 'complete', and 'error'.
 * Each transaction context uses exactly one tcert.
 * 
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 * 修改內容：將CrptoSuite参数去掉，使用另外实现的加密模块。
 */
public class TransactionContext {
    private static final Config config = Config.getConfig();
    //    private static final Log logger = LogFactory.getLog(TransactionContext.class);
    //TODO right now the server does not care need to figure out
    private final ByteString nonce = ByteString.copyFrom(Utils.generateNonce());
    private final ILocalSigner signer;
    private final User user;
    private final Group channel;
    private final String txID;
    private final Identities.SerializedIdentity identity;
    Timestamp currentTimeStamp = null;
    private boolean verify = true;
    //private List<String> attrs;
    private long proposalWaitTime = config.getProposalWaitTime();

    public TransactionContext(Group channel, User user) {

        this.user = user;
        this.channel = channel;
        //TODO clean up when public classes are interfaces.
        this.verify = !"".equals(channel.getName());  //if name is not blank not system channel and need verify.

        //  this.txID = transactionID;
        signer = new LocalSigner();
        identity = ProtoUtils.createSerializedIdentity(getUser());

        ByteString no = getNonce();

        ByteString comp = no.concat(identity.toByteString());

        byte[] txh = new byte[0];

        try {
            txh = MspStore.getInstance().getCsp().hash(comp.toByteArray(), null);
        } catch (JavaChainException e) {
            e.printStackTrace();
            txh = null;//沒有正確獲取txh
        }


        //    txID = Hex.encodeHexString(txh);
        txID = new String(Utils.toHexString(txh));

    }

    public Identities.SerializedIdentity getIdentity() {

        return identity;

    }

    public long getEpoch() {
        return 0;
    }

    /**
     * Get the user with which this transaction context is associated.
     *
     * @return The user
     */
    public User getUser() {
        return user;
    }

    /**
     * Get the attribute names associated with this transaction context.
     *
     * @return the attributes.
     */
    //public List<String> getAttrs() {
    //    return this.attrs;
    //}

    /**
     * Set the attributes for this transaction context.
     *
     * @param attrs the attributes.
     */
    //public void setAttrs(List<String> attrs) {
    //    this.attrs = attrs;
    //}

    /**
     * Get the channel with which this transaction context is associated.
     *
     * @return The channel
     */
    public Group getGroup() {
        return this.channel;
    }

    /**
     * Gets the timeout for a single proposal request to endorser in milliseconds.
     *
     * @return the timeout for a single proposal request to endorser in milliseconds
     */
    public long getProposalWaitTime() {
        return proposalWaitTime;
    }

    /**
     * Sets the timeout for a single proposal request to endorser in milliseconds.
     *
     * @param proposalWaitTime the timeout for a single proposal request to endorser in milliseconds
     */
    public void setProposalWaitTime(long proposalWaitTime) {
        this.proposalWaitTime = proposalWaitTime;
    }

    public Timestamp getFabricTimestamp() {
        if (currentTimeStamp == null) {

            currentTimeStamp = ProtoUtils.getCurrentFabricTimestamp();
        }
        return currentTimeStamp;
    }

    public ByteString getNonce() {

        return nonce;

    }

    public void verify(boolean verify) {
        this.verify = verify;
    }

    public boolean getVerify() {
        return verify;
    }

    public String getGroupID() {
        return getGroup().getName();
    }

    public String getTxID() {
        return txID;
    }

    byte[] sign(byte[] b) throws CryptoException {
        return signer.sign(b);
    }

    public ByteString signByteString(byte[] b) throws CryptoException {
        return ByteString.copyFrom(sign(b));
    }

    public ByteString signByteStrings(ByteString... bs) throws CryptoException {
        if (bs == null) {
            return null;
        }
        if (bs.length == 0) {
            return null;
        }
        if (bs.length == 1 && bs[0] == null) {
            return null;
        }

        ByteString f = bs[0];
        for (int i = 1; i < bs.length; ++i) {
            f = f.concat(bs[i]);

        }
        return ByteString.copyFrom(sign(f.toByteArray()));
    }

    public ByteString[] signByteStrings(User[] users, ByteString... bs) throws CryptoException {
        if (bs == null) {
            return null;
        }
        if (bs.length == 0) {
            return null;
        }
        if (bs.length == 1 && bs[0] == null) {
            return null;
        }

        ByteString f = bs[0];
        for (int i = 1; i < bs.length; ++i) {
            f = f.concat(bs[i]);
        }

        final byte[] signbytes = f.toByteArray();

        ByteString[] ret = new ByteString[users.length];

        int i = -1;
        for (User user : users) {
            ret[++i] = ByteString.copyFrom(signer.sign(signbytes));
        }
        return ret;
    }

    public TransactionContext retryTransactionSameContext() {
        return new TransactionContext(channel, user);
    }

    @Override
    public String toString() {
        return "TransactionContext{" +
                "nonce=" + nonce +
                ", signer=" + signer +
                ", user=" + user +
                ", channel=" + channel +
                ", txID='" + txID + '\'' +
                ", identity=" + identity +
                ", currentTimeStamp=" + currentTimeStamp +
                ", verify=" + verify +
                ", proposalWaitTime=" + proposalWaitTime +
                '}';
    }
}  // end TransactionContext
