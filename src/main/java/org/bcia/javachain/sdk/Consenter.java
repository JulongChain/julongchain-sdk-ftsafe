/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.io.Serializable;
import java.util.Properties;

import io.netty.util.internal.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.exception.TransactionException;
import org.bcia.javachain.protos.common.Common;
import org.bcia.javachain.protos.consenter.Ab;
import org.bcia.javachain.protos.consenter.Ab.DeliverResponse;

import static java.lang.String.format;
import static org.bcia.javachain.sdk.helper.Utils.checkGrpcUrl;

/**
 * The Consenter class represents a orderer to which SDK sends deploy, invoke, or query requests.
 * 
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
public class Consenter implements Serializable {
    private static final Log logger = LogFactory.getLog(Consenter.class);
    private static final long serialVersionUID = 4281642068914263247L;
    private final Properties properties;
    private final String name;
    private final String url;
    private transient boolean shutdown = false;
    private Group channel;
    private transient volatile ConsenterClient ordererClient = null;
    private transient byte[] clientTLSCertificateDigest;

    Consenter(String name, String url, Properties properties) throws InvalidArgumentException {

        if (StringUtil.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Invalid name for orderer");
        }
        Exception e = checkGrpcUrl(url);
        if (e != null) {
            throw new InvalidArgumentException(e);
        }

        this.name = name;
        this.url = url;
        this.properties = properties == null ? null : (Properties) properties.clone(); //keep our own copy.

    }

    static Consenter createNewInstance(String name, String url, Properties properties) throws InvalidArgumentException {
        return new Consenter(name, url, properties);

    }

    byte[] getClientTLSCertificateDigest() {
        if (null == clientTLSCertificateDigest) {
            clientTLSCertificateDigest = new Endpoint(url, properties).getClientTLSCertificateDigest();
        }
        return clientTLSCertificateDigest;
    }

    /**
     * Get Consenter properties.
     *
     * @return properties
     */

    public Properties getProperties() {

        return properties == null ? null : (Properties) properties.clone();
    }

    /**
     * Return Consenter's name
     *
     * @return orderer's name.
     */
    public String getName() {
        return name;
    }

    /**
     * getUrl - the Grpc url of the Consenter
     *
     * @return the Grpc url of the Consenter
     */
    public String getUrl() {
        return url;
    }

    void unsetGroup() {

        channel = null;

    }

    /**
     * Get the channel of which this orderer is a member.
     *
     * @return {Group} The channel of which this orderer is a member.
     */
    Group getGroup() {
        return channel;
    }

    void setGroup(Group channel) throws InvalidArgumentException {
        if (channel == null) {
            throw new InvalidArgumentException("setGroup Group can not be null");
        }

        if (null != this.channel && this.channel != channel) {
            throw new InvalidArgumentException(format("Can not add orderer %s to channel %s because it already belongs to channel %s.",
                    name, channel.getName(), this.channel.getName()));
        }

        this.channel = channel;

    }

    /**
     * Send transaction to Order
     *
     * @param transaction transaction to be sent
     */

    Ab.BroadcastResponse sendTransaction(Common.Envelope transaction) throws Exception {
        if (shutdown) {
            throw new TransactionException(format("Consenter %s was shutdown.", name));
        }

        logger.debug(format("Order.sendTransaction name: %s, url: %s", name, url));

        ConsenterClient localConsenterClient = ordererClient;

        if (localConsenterClient == null || !localConsenterClient.isGroupActive()) {
            ordererClient = new ConsenterClient(this, new Endpoint(url, properties).getGroupBuilder(), properties);
            localConsenterClient = ordererClient;
        }

        try {

            return localConsenterClient.sendTransaction(transaction);
        } catch (Throwable t) {
            ordererClient = null;
            throw t;

        }

    }

    DeliverResponse[] sendDeliver(Common.Envelope transaction) throws TransactionException {

        if (shutdown) {
            throw new TransactionException(format("Consenter %s was shutdown.", name));
        }

        ConsenterClient localConsenterClient = ordererClient;

        logger.debug(format("Order.sendDeliver name: %s, url: %s", name, url));
        if (localConsenterClient == null || !localConsenterClient.isGroupActive()) {
            localConsenterClient = new ConsenterClient(this, new Endpoint(url, properties).getGroupBuilder(), properties);
            ordererClient = localConsenterClient;
        }

        try {

            return localConsenterClient.sendDeliver(transaction);
        } catch (Throwable t) {
            ordererClient = null;
            throw t;

        }

    }

    synchronized void shutdown(boolean force) {
        if (shutdown) {
            return;
        }
        shutdown = true;
        channel = null;

        if (ordererClient != null) {
            ConsenterClient torderClientDeliver = ordererClient;
            ordererClient = null;
            torderClientDeliver.shutdown(force);
        }

    }

    @Override
    protected void finalize() throws Throwable {
        shutdown(true);
        super.finalize();
    }

    @Override
    public String toString() {
        return "Consenter: " + name + "(" + url + ")";
    }
} // end Consenter
