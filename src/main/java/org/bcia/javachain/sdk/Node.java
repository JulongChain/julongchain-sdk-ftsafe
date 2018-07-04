/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at`
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.bcia.javachain.sdk;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ExecutorService;

import com.google.common.util.concurrent.ListenableFuture;
import io.netty.util.internal.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bcia.javachain.sdk.Group.NodeOptions;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.exception.NodeException;
import org.bcia.javachain.sdk.exception.TransactionException;
import org.bcia.javachain.sdk.helper.Config;
import org.bcia.javachain.sdk.transaction.TransactionContext;
import org.bcia.javachain.protos.node.ProposalPackage;
import org.bcia.javachain.protos.node.ProposalResponsePackage;

import static java.lang.String.format;
import static org.bcia.javachain.sdk.helper.Utils.checkGrpcUrl;

/**
 * The Node class represents a peer to which SDK sends deploy, or query proposals requests.
 * 
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
public class Node implements Serializable {

    private static final Log logger = LogFactory.getLog(Node.class);
    private static final long serialVersionUID = -5273194649991828876L;
    private static final Config config = Config.getConfig();
    private static final long PEER_EVENT_RETRY_WAIT_TIME = config.getNodeRetryWaitTime();
    private final Properties properties;
    private final String name;
    private final String url;
    private transient volatile EndorserClient endorserClent;
    private transient NodeEventServiceClient peerEventingClient;
    private transient boolean shutdown = false;
    private Group channel;
    private transient TransactionContext transactionContext;
    private transient long lastConnectTime;
    private transient long reconnectCount;
    private transient BlockEvent lastBlockEvent;
    private transient long lastBlockNumber;

    Node(String name, String grpcURL, Properties properties) throws InvalidArgumentException {

        Exception e = checkGrpcUrl(grpcURL);
        if (e != null) {
            throw new InvalidArgumentException("Bad peer url.", e);

        }

        if (StringUtil.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Invalid name for peer");
        }

        this.url = grpcURL;
        this.name = name;
        this.properties = properties == null ? null : (Properties) properties.clone(); //keep our own copy.
        reconnectCount = 0L;

    }

    static Node createNewInstance(String name, String grpcURL, Properties properties) throws InvalidArgumentException {

        return new Node(name, grpcURL, properties);
    }

    /**
     * Node's name
     *
     * @return return the peer's name.
     */

    public String getName() {

        return name;
    }

    public Properties getProperties() {

        return properties == null ? null : (Properties) properties.clone();
    }

    void unsetGroup() {
        channel = null;
    }

    BlockEvent getLastBlockEvent() {
        return lastBlockEvent;
    }



    ExecutorService getExecutorService() {
        return channel.getExecutorService();
    }

    void initiateEventing(TransactionContext transactionContext, NodeOptions peersOptions) throws TransactionException {

        this.transactionContext = transactionContext.retryTransactionSameContext();

        if (peerEventingClient == null) {

            //NodeEventServiceClient(Node peer, ManagedChannelBuilder<?> channelBuilder, Properties properties)
            //   peerEventingClient = new NodeEventServiceClient(this, new HashSet<Group>(Arrays.asList(new Group[] {channel})));

            peerEventingClient = new NodeEventServiceClient(this, new Endpoint(url, properties), properties, peersOptions);

            peerEventingClient.connect(transactionContext);

        }

    }

    /**
     * The channel the peer is set on.
     *
     * @return
     */

    Group getGroup() {

        return channel;

    }

    /**
     * Set the channel the peer is on.
     *
     * @param channel
     */

    void setGroup(Group channel) throws InvalidArgumentException {

        if (null != this.channel) {
            throw new InvalidArgumentException(format("Can not add peer %s to channel %s because it already belongs to channel %s.",
                    name, channel.getName(), this.channel.getName()));
        }

        this.channel = channel;

    }

    /**
     * Get the URL of the peer.
     *
     * @return {string} Get the URL associated with the peer.
     */
    public String getUrl() {

        return url;
    }

    /**
     * for use in list of peers comparisons , e.g. list.contains() calls
     *
     * @param otherNode the peer instance to compare against
     * @return true if both peer instances have the same name and url
     */
    @Override
    public boolean equals(Object otherNode) {
        if (this == otherNode) {
            return true;
        }
        if (otherNode == null) {
            return false;
        }
        if (!(otherNode instanceof Node)) {
            return false;
        }
        Node p = (Node) otherNode;
        return Objects.equals(this.name, p.name) && Objects.equals(this.url, p.url);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, url);
    }

    ListenableFuture<ProposalResponsePackage.ProposalResponse> sendProposalAsync(ProposalPackage.SignedProposal proposal)
            throws NodeException, InvalidArgumentException {
        checkSendProposal(proposal);

        logger.debug(format("peer.sendProposalAsync name: %s, url: %s", name, url));

        EndorserClient localEndorserClient = endorserClent; //work off thread local copy.

        if (null == localEndorserClient || !localEndorserClient.isGroupActive()) {
            endorserClent = new EndorserClient(new Endpoint(url, properties).getGroupBuilder());
            localEndorserClient = endorserClent;
        }

        try {
            return localEndorserClient.sendProposalAsync(proposal);
        } catch (Throwable t) {
            endorserClent = null;
            throw t;
        }
    }

    private void checkSendProposal(ProposalPackage.SignedProposal proposal) throws
            NodeException, InvalidArgumentException {

        if (shutdown) {
            throw new NodeException(format("Node %s was shutdown.", name));
        }
        if (proposal == null) {
            throw new NodeException("Proposal is null");
        }
        Exception e = checkGrpcUrl(url);
        if (e != null) {
            throw new InvalidArgumentException("Bad peer url.", e);

        }
    }

    synchronized void shutdown(boolean force) {
        if (shutdown) {
            return;
        }
        shutdown = true;
        channel = null;
        lastBlockEvent = null;
        lastBlockNumber = 0;

        EndorserClient lendorserClent = endorserClent;

        //allow resources to finalize

        endorserClent = null;

        if (lendorserClent != null) {

            lendorserClent.shutdown(force);
        }

        NodeEventServiceClient lpeerEventingClient = peerEventingClient;
        peerEventingClient = null;

        if (null != lpeerEventingClient) {
            // NodeEventServiceClient peerEventingClient1 = peerEventingClient;

            lpeerEventingClient.shutdown(force);
        }
    }

    @Override
    protected void finalize() throws Throwable {
        shutdown(true);
        super.finalize();
    }

    void reconnectNodeEventServiceClient(final NodeEventServiceClient failedNodeEventServiceClient,
                                         final Throwable throwable) {
        if (shutdown) {
            logger.debug("Not reconnecting NodeEventServiceClient shutdown ");
            return;

        }
        NodeEventingServiceDisconnected ldisconnectedHandler = disconnectedHandler;
        if (null == ldisconnectedHandler) {

            return; // just wont reconnect.

        }
        TransactionContext ltransactionContext = transactionContext;
        if (ltransactionContext == null) {

            logger.warn("Not reconnecting NodeEventServiceClient no transaction available ");
            return;
        }

        final TransactionContext fltransactionContext = ltransactionContext.retryTransactionSameContext();

        final ExecutorService executorService = getExecutorService();
        final NodeOptions peerOptions = null != failedNodeEventServiceClient.getNodeOptions() ? failedNodeEventServiceClient.getNodeOptions() :
                NodeOptions.createNodeOptions();
        if (executorService != null && !executorService.isShutdown() && !executorService.isTerminated()) {

            executorService.execute(() -> ldisconnectedHandler.disconnected(new NodeEventingServiceDisconnectEvent() {
                @Override
                public BlockEvent getLatestBLockReceived() {
                    return lastBlockEvent;
                }

                @Override
                public long getLastConnectTime() {
                    return lastConnectTime;
                }

                @Override
                public long getReconnectCount() {
                    return reconnectCount;
                }

                @Override
                public Throwable getExceptionThrown() {
                    return throwable;
                }

                @Override
                public void reconnect(Long startBLockNumber) throws TransactionException {
                    logger.trace("reconnecting startBLockNumber" + startBLockNumber);
                    ++reconnectCount;

                    if (startBLockNumber == null) {
                        peerOptions.startEventsNewest();
                    } else {
                        peerOptions.startEvents(startBLockNumber);
                    }



                    NodeEventServiceClient lpeerEventingClient = new NodeEventServiceClient(Node.this,
                            new Endpoint(url, properties), properties, peerOptions);
                    lpeerEventingClient.connect(fltransactionContext);
                    peerEventingClient = lpeerEventingClient;

                }
            }));

        }

    }

    void setLastConnectTime(long lastConnectTime) {
        this.lastConnectTime = lastConnectTime;
    }

    void resetReconnectCount() {
        reconnectCount = 0L;
    }

    long getReconnectCount() {
        return reconnectCount;
    }

    public interface NodeEventingServiceDisconnected {

        /**
         * Called when a disconnect is detected in peer eventing service.
         *
         * @param event
         */
        void disconnected(NodeEventingServiceDisconnectEvent event);

    }

    public interface NodeEventingServiceDisconnectEvent {

        /**
         * The latest BlockEvent received by peer eventing service.
         *
         * @return The latest BlockEvent.
         */

        BlockEvent getLatestBLockReceived();

        /**
         * Last connect time
         *
         * @return Last connect time as reported by System.currentTimeMillis()
         */
        long getLastConnectTime();

        /**
         * Number reconnection attempts since last disconnection.
         *
         * @return reconnect attempts.
         */

        long getReconnectCount();

        /**
         * Last exception throw for failing connection
         *
         * @return
         */

        Throwable getExceptionThrown();

        void reconnect(Long startEvent) throws TransactionException;

    }

    private transient NodeEventingServiceDisconnected disconnectedHandler = getDefaultDisconnectHandler();

    private static NodeEventingServiceDisconnected getDefaultDisconnectHandler() {
        return new NodeEventingServiceDisconnected() { //default.
            @Override
            public synchronized void disconnected(final NodeEventingServiceDisconnectEvent event) {

                BlockEvent lastBlockEvent = event.getLatestBLockReceived();

                Long startBlockNumber = null;

                if (null != lastBlockEvent) {

                    startBlockNumber = lastBlockEvent.getBlockNumber();
                }

                if (0 != event.getReconnectCount()) {
                    try {
                        Thread.sleep(PEER_EVENT_RETRY_WAIT_TIME);
                    } catch (InterruptedException e) {

                    }
                }

                try {
                    event.reconnect(startBlockNumber);
                } catch (TransactionException e) {
                    e.printStackTrace();
                }

            }

        };
    }

    /**
     * Set class to handle Event hub disconnects
     *
     * @param newNodeEventingServiceDisconnectedHandler New handler to replace.  If set to null no retry will take place.
     * @return the old handler.
     */

    public NodeEventingServiceDisconnected setNodeEventingServiceDisconnected(NodeEventingServiceDisconnected newNodeEventingServiceDisconnectedHandler) {
        NodeEventingServiceDisconnected ret = disconnectedHandler;
        disconnectedHandler = newNodeEventingServiceDisconnectedHandler;
        return ret;
    }

    synchronized void setLastBlockSeen(BlockEvent lastBlockSeen) {
        long newLastBlockNumber = lastBlockSeen.getBlockNumber();
        // overkill but make sure.
        if (lastBlockNumber < newLastBlockNumber) {
            lastBlockNumber = newLastBlockNumber;
            this.lastBlockEvent = lastBlockSeen;
        }
    }

    /**
     * Possible roles a peer can perform.
     */
    public enum NodeRole {
        /**
         * Endorsing peer installs and runs chaincode.
         */
        ENDORSING_PEER("endorsingNode"),
        /**
         * SmartContract query peer will be used to invoke chaincode on chaincode query requests.
         */
        CHAINCODE_QUERY("chaincodeQuery"),
        /**
         * Ledger Query will be used when query ledger operations are requested.
         */
        LEDGER_QUERY("ledgerQuery"),
        /**
         * Node will monitor block events for the channel it belongs to.
         */
        EVENT_SOURCE("eventSource");

        /**
         * All roles.
         */
        public static final EnumSet<NodeRole> ALL = EnumSet.allOf(NodeRole.class);
        /**
         * All roles except event source.
         */
        public static final EnumSet<NodeRole> NO_EVENT_SOURCE = EnumSet.complementOf(EnumSet.of(NodeRole.EVENT_SOURCE));
        private final String propertyName;

        NodeRole(String propertyName) {
            this.propertyName = propertyName;
        }

        public String getPropertyName() {
            return propertyName;
        }
    }

    @Override
    public String toString() {
        return "Node " + name + " url: " + url;

    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {

        in.defaultReadObject();
        disconnectedHandler = getDefaultDisconnectHandler();

    }
} // end Node
