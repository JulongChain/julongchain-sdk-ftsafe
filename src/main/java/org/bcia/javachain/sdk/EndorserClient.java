/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
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

package org.bcia.javachain.sdk;

import java.util.concurrent.TimeUnit;

import com.google.common.util.concurrent.ListenableFuture;
import io.grpc.ConnectivityState;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bcia.javachain.sdk.exception.NodeException;
import org.bcia.javachain.protos.node.EndorserGrpc;
import org.bcia.javachain.protos.node.ProposalPackage;
import org.bcia.javachain.protos.node.ProposalResponsePackage;

/**
 * Sample client code that makes gRPC calls to the server.
 * 
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
class EndorserClient {
    private static final Log logger = LogFactory.getLog(EndorserClient.class);

    private ManagedChannel managedGroup;
    private EndorserGrpc.EndorserBlockingStub blockingStub;
    private EndorserGrpc.EndorserFutureStub futureStub;
    private boolean shutdown = false;

    /**
     * Construct client for accessing Node server using the existing channel.
     *
     * @param channelBuilder The GroupBuilder to build the endorser client
     */
    EndorserClient(ManagedChannelBuilder<?> channelBuilder) {
        managedGroup = channelBuilder.build();
        blockingStub = EndorserGrpc.newBlockingStub(managedGroup);
        futureStub = EndorserGrpc.newFutureStub(managedGroup);
    }

    synchronized void shutdown(boolean force) {
        if (shutdown) {
            return;
        }
        shutdown = true;
        ManagedChannel lchannel = managedGroup;
        // let all referenced resource finalize
        managedGroup = null;
        blockingStub = null;
        futureStub = null;

        if (lchannel == null) {
            return;
        }
        if (force) {
            lchannel.shutdownNow();
        } else {
            boolean isTerminated = false;

            try {
                isTerminated = lchannel.shutdown().awaitTermination(3, TimeUnit.SECONDS);
            } catch (Exception e) {
                logger.debug(e); //best effort
            }
            if (!isTerminated) {
                lchannel.shutdownNow();
            }
        }
    }

    public ListenableFuture<ProposalResponsePackage.ProposalResponse> sendProposalAsync(ProposalPackage.SignedProposal proposal) throws NodeException {
        if (shutdown) {
            throw new NodeException("Shutdown");
        }
        return futureStub.processProposal(proposal);
    }


    boolean isGroupActive() {
        ManagedChannel lchannel = managedGroup;
        return lchannel != null && !lchannel.isShutdown() && !lchannel.isTerminated() && ConnectivityState.READY.equals(lchannel.getState(true));
    }

    @Override
    public void finalize() {
        shutdown(true);
    }
}
