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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bcia.javachain.sdk.exception.CryptoException;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.exception.NetworkConfigurationException;
import org.bcia.javachain.sdk.exception.ProposalException;
import org.bcia.javachain.sdk.exception.TransactionException;
import org.bcia.javachain.sdk.helper.Utils;
import org.bcia.javachain.sdk.security.CryptoSuite;
import org.bcia.julongchain.protos.node.Query.SmartContractInfo;

import static java.lang.String.format;
import static org.bcia.javachain.sdk.User.userContextCheck;


/**
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
public class HFClient {

    private CryptoSuite cryptoSuite;

    static {

        if (null == System.getProperty("org.bcia.javachain.sdk.logGRPC")) {
            // Turn this off by default!
            Logger.getLogger("io.netty").setLevel(Level.OFF);
            Logger.getLogger("io.grpc").setLevel(Level.OFF);

        }
    }

    private final ExecutorService executorService = Executors.newCachedThreadPool(r -> {
        Thread t = Executors.defaultThreadFactory().newThread(r);
        t.setDaemon(true);
        return t;
    });

    ExecutorService getExecutorService() {
        return executorService;
    }

    private static final Log logger = LogFactory.getLog(HFClient.class);

    private final Map<String, Group> channels = new HashMap<>();

    public User getUserContext() {
        return userContext;
    }

    private User userContext;

    private HFClient() {

    }

    public CryptoSuite getCryptoSuite() {
        return cryptoSuite;
    }

    public void setCryptoSuite(CryptoSuite cryptoSuite) throws CryptoException, InvalidArgumentException {
        if (null == cryptoSuite) {
            throw new InvalidArgumentException("CryptoSuite paramter is null.");
        }
        if (this.cryptoSuite != null && cryptoSuite != this.cryptoSuite) {
            throw new InvalidArgumentException("CryptoSuite may only be set once.");

        }
        //        if (cryptoSuiteFactory == null) {
        //            cryptoSuiteFactory = cryptoSuite.getCryptoSuiteFactory();
        //        } else {
        //            if (cryptoSuiteFactory != cryptoSuite.getCryptoSuiteFactory()) {
        //                throw new InvalidArgumentException("CryptoSuite is not derivied from cryptosuite factory");
        //            }
        //        }

        this.cryptoSuite = cryptoSuite;

    }

    /**
     * createNewInstance create a new instance of the HFClient
     *
     * @return client
     */
    public static HFClient createNewInstance() {
        return new HFClient();
    }

    /**
     * Configures a channel based on information loaded from a Network Config file.
     * Note that it is up to the caller to initialize the returned channel.
     *
     * @param channelName The name of the channel to be configured
     * @param networkConfig The network configuration to use to configure the channel
     * @return The configured channel, or null if the channel is not defined in the configuration
     * @throws InvalidArgumentException
     */
    public Group loadGroupFromConfig(String channelName, NetworkConfig networkConfig) throws InvalidArgumentException, NetworkConfigurationException {
        clientCheck();

        // Sanity checks
        if (channelName == null || channelName.isEmpty()) {
            throw new InvalidArgumentException("channelName must be specified");
        }

        if (networkConfig == null) {
            throw new InvalidArgumentException("networkConfig must be specified");
        }

        if (channels.containsKey(channelName)) {
            throw new InvalidArgumentException(format("Group with name %s already exists", channelName));
        }

        return networkConfig.loadGroup(this, channelName);
    }


    /**
     * newGroup - already configured channel.
     *
     * @param name
     * @return a new channel.
     * @throws InvalidArgumentException
     */

    public Group newGroup(String name) throws InvalidArgumentException {
        clientCheck();
        if (Utils.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Group name can not be null or empty string.");
        }

        synchronized (channels) {

            if (channels.containsKey(name)) {
                throw new InvalidArgumentException(format("Group by the name %s already exists", name));
            }
            logger.trace("Creating channel :" + name);
            Group newGroup = Group.createNewInstance(name, this);

            channels.put(name, newGroup);
            return newGroup;

        }

    }

    /**
     * 创建群组
     *
     * @param name                           The channel's name
     * @param orderer                        Consenter to create the channel with.
     * @param channelConfiguration           Group configuration data.
     * @param channelConfigurationSignatures byte arrays containing ConfigSignature's proto serialized.
     *                                       See {@link Group#getGroupConfigurationSignature} on how to create
     * @return a new channel.
     * @throws TransactionException
     * @throws InvalidArgumentException
     */

    public Group newGroup(String name, Consenter orderer, GroupConfiguration channelConfiguration,
            byte[]... channelConfigurationSignatures) throws TransactionException, InvalidArgumentException {

        clientCheck();
        if (Utils.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Group name can not be null or empty string.");
        }

        synchronized (channels) {

            if (channels.containsKey(name)) {
                throw new InvalidArgumentException(format("Group by the name %s already exits", name));
            }

            logger.trace("Creating channel :" + name);

            Group newGroup = Group.createNewInstance(name, this, orderer, channelConfiguration, channelConfigurationSignatures);

            channels.put(name, newGroup);
            return newGroup;

        }

    }

    /**
     * Deserialize a channel serialized by {@link Group#serializeGroup()}
     *
     * @param file a file which contains the bytes to be deserialized.
     * @return A Group that has not been initialized.
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InvalidArgumentException
     */

    public Group deSerializeGroup(File file) throws IOException, ClassNotFoundException, InvalidArgumentException {

        if (null == file) {
            throw new InvalidArgumentException("File parameter may not be null");
        }

        return deSerializeGroup(Files.readAllBytes(Paths.get(file.getAbsolutePath())));
    }

    /**
     * Deserialize a channel serialized by {@link Group#serializeGroup()}
     *
     * @param channelBytes bytes to be deserialized.
     * @return A Group that has not been initialized.
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InvalidArgumentException
     */

    public Group deSerializeGroup(byte[] channelBytes)
            throws IOException, ClassNotFoundException, InvalidArgumentException {

        Group channel;
        ObjectInputStream in = null;
        try {
            in = new ObjectInputStream(new ByteArrayInputStream(channelBytes));
            channel = (Group) in.readObject();
            final String name = channel.getName();
            synchronized (channels) {
                if (null != getGroup(name)) {
                    channel.shutdown(true);
                    throw new InvalidArgumentException(format("Group %s already exists in the client", name));
                }
                channels.put(name, channel);
                channel.client = this;
            }

        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException e) {
                // Best effort here.
                logger.error(e);
            }
        }

        return channel;

    }

    /**
     * newNode create a new peer
     *
     * @param name       name of peer.
     * @param grpcURL    to the peer's location
     * @param properties <p>
     *                   Supported properties
     *                   <ul>
     *                   <li>pemFile - File location for x509 pem certificate for SSL.</li>
     *                   <li>trustServerCertificate - boolen(true/false) override CN to match pemFile certificate -- for development only.
     *                   If the pemFile has the target server's certificate (instead of a CA Root certificate),
     *                   instruct the TLS client to trust the CN value of the certificate in the pemFile,
     *                   useful in development to get past default server hostname verification during
     *                   TLS handshake, when the server host name does not match the certificate.
     *                   </li>
     *                   <li>clientKeyFile - File location for private key pem for mutual TLS</li>
     *                   <li>clientCertFile - File location for x509 pem certificate for mutual TLS</li>
     *                   <li>clientKeyBytes - Private key pem bytes for mutual TLS</li>
     *                   <li>clientCertBytes - x509 pem certificate bytes for mutual TLS</li>
     *                   <li>hostnameOverride - Specify the certificates CN -- for development only.
     *                   <li>sslProvider - Specify the SSL provider, openSSL or JDK.</li>
     *                   <li>negotiationType - Specify the type of negotiation, TLS or plainText.</li>
     *                   <li>If the pemFile does not represent the server certificate, use this property to specify the URI authority
     *                   (a.k.a hostname) expected in the target server's certificate. This is required to get past default server
     *                   hostname verifications during TLS handshake.
     *                   </li>
     *                   <li>
     *                   peerEventRegistrationWaitTime - Time in milliseconds to wait for peer eventing service registration.
     *                   </li>
     *                   <li>
     *                   grpc.NettyChannelBuilderOption.&lt;methodName&gt;  where methodName is any method on
     *                   grpc ManagedChannelBuilder.  If more than one argument to the method is needed then the
     *                   parameters need to be supplied in an array of Objects.
     *                   </li>
     *                   </ul>
     * @return Node
     * @throws InvalidArgumentException
     */

    public Node newNode(String name, String grpcURL, Properties properties) throws InvalidArgumentException {
        clientCheck();
        return Node.createNewInstance(name, grpcURL, properties);
    }

    /**
     * newNode create a new peer
     *
     * @param name
     * @param grpcURL to the peer's location
     * @return Node
     * @throws InvalidArgumentException
     */

    public Node newNode(String name, String grpcURL) throws InvalidArgumentException {
        clientCheck();
        return Node.createNewInstance(name, grpcURL, null);
    }

    /**
     * getGroup by name
     *
     * @param name The channel name
     * @return a channel (or null if the channel does not exist)
     */

    public Group getGroup(String name) {
        return channels.get(name);
    }

    /**
     * newInstallProposalRequest get new Install proposal request.
     *
     * @return InstallProposalRequest
     */
    public InstallProposalRequest newInstallProposalRequest() {
        return new InstallProposalRequest(userContext);
    }

    /**
     * newInstantiationProposalRequest get new instantiation proposal request.
     *
     * @return InstantiateProposalRequest
     */

    public InstantiateProposalRequest newInstantiationProposalRequest() {
        return new InstantiateProposalRequest(userContext);
    }

    public UpgradeProposalRequest newUpgradeProposalRequest() {
        return new UpgradeProposalRequest(userContext);
    }

    /**
     * newTransactionProposalRequest  get new transaction proposal request.
     *
     * @return TransactionProposalRequest
     */

    public TransactionProposalRequest newTransactionProposalRequest() {
        return TransactionProposalRequest.newInstance(userContext);
    }

    /**
     * newQueryProposalRequest get new query proposal request.
     *
     * @return QueryBySmartContractRequest
     */

    public QueryBySmartContractRequest newQueryProposalRequest() {
        return QueryBySmartContractRequest.newInstance(userContext);
    }

    /**
     * Set the User context for this client.
     *
     * @param userContext
     * @return the old user context. Maybe null if never set!
     * @throws InvalidArgumentException
     */
    public User setUserContext(User userContext) throws InvalidArgumentException {

        if (null == cryptoSuite) {
            throw new InvalidArgumentException("No cryptoSuite has been set.");
        }
        userContextCheck(userContext);

        User ret = this.userContext;
        this.userContext = userContext;

        logger.debug(
                format("Setting user context to MSPID: %s user: %s", userContext.getMspId(), userContext.getName()));

        return ret;
    }

    /**
     * Create a new Eventhub.
     *
     * @param name       name of Consenter.
     * @param grpcURL    url location of orderer grpc or grpcs protocol.
     * @param properties <p>
     *                   Supported properties
     *                   <ul>
     *                   <li>pemFile - File location for x509 pem certificate for SSL.</li>
     *                   <li>trustServerCertificate - boolean(true/false) override CN to match pemFile certificate -- for development only.
     *                   If the pemFile has the target server's certificate (instead of a CA Root certificate),
     *                   instruct the TLS client to trust the CN value of the certificate in the pemFile,
     *                   useful in development to get past default server hostname verification during
     *                   TLS handshake, when the server host name does not match the certificate.
     *                   </li>
     *                   <li>clientKeyFile - File location for PKCS8-encoded private key pem for mutual TLS</li>
     *                   <li>clientCertFile - File location for x509 pem certificate for mutual TLS</li>
     *                   <li>hostnameOverride - Specify the certificates CN -- for development only.
     *                   <li>sslProvider - Specify the SSL provider, openSSL or JDK.</li>
     *                   <li>negotiationType - Specify the type of negotiation, TLS or plainText.</li>
     *                   <li>If the pemFile does not represent the server certificate, use this property to specify the URI authority
     *                   (a.k.a hostname) expected in the target server's certificate. This is required to get past default server
     *                   hostname verifications during TLS handshake.
     *                   </li>
     *                   <li>
     *                   grpc.NettyChannelBuilderOption.&lt;methodName&gt;  where methodName is any method on
     *                   grpc ManagedChannelBuilder.  If more than one argument to the method is needed then the
     *                   parameters need to be supplied in an array of Objects.
     *                   </li>
     *                   </ul>
     * @return The orderer.
     * @throws InvalidArgumentException
     */

    public EventHub newEventHub(String name, String grpcURL, Properties properties) throws InvalidArgumentException {
        clientCheck();
        return EventHub.createNewInstance(name, grpcURL, executorService, properties);
    }

    /**
     * Create a new event hub
     *
     * @param name    Name of eventhup should match peer's name it's associated with.
     * @param grpcURL The http url location of the event hub
     * @return event hub
     * @throws InvalidArgumentException
     */

    public EventHub newEventHub(String name, String grpcURL) throws InvalidArgumentException {
        clientCheck();
        return newEventHub(name, grpcURL, null);
    }

    /**
     * Create a new urlConsenter.
     *
     * @param name    name of the orderer.
     * @param grpcURL url location of orderer grpc or grpcs protocol.
     * @return a new Consenter.
     * @throws InvalidArgumentException
     */

    public Consenter newConsenter(String name, String grpcURL) throws InvalidArgumentException {
        clientCheck();
        return newConsenter(name, grpcURL, null);
    }

    /**
     * Create a new orderer.
     *
     * @param name       name of Consenter.
     * @param grpcURL    url location of orderer grpc or grpcs protocol.
     * @param properties <p>
     *                   Supported properties
     *                   <ul>
     *                   <li>pemFile - File location for x509 pem certificate for SSL.</li>
     *                   <li>trustServerCertificate - boolean(true/false) override CN to match pemFile certificate -- for development only.
     *                   If the pemFile has the target server's certificate (instead of a CA Root certificate),
     *                   instruct the TLS client to trust the CN value of the certificate in the pemFile,
     *                   useful in development to get past default server hostname verification during
     *                   TLS handshake, when the server host name does not match the certificate.
     *                   </li>
     *                   <li>clientKeyFile - File location for private key pem for mutual TLS</li>
     *                   <li>clientCertFile - File location for x509 pem certificate for mutual TLS</li>
     *                   <li>clientKeyBytes - Private key pem bytes for mutual TLS</li>
     *                   <li>clientCertBytes - x509 pem certificate bytes for mutual TLS</li>
     *                   <li>sslProvider - Specify the SSL provider, openSSL or JDK.</li>
     *                   <li>negotiationType - Specify the type of negotiation, TLS or plainText.</li>
     *                   <li>hostnameOverride - Specify the certificates CN -- for development only.
     *                   If the pemFile does not represent the server certificate, use this property to specify the URI authority
     *                   (a.k.a hostname) expected in the target server's certificate. This is required to get past default server
     *                   hostname verifications during TLS handshake.
     *                   </li>
     *                   <li>
     *                   grpc.NettyChannelBuilderOption.&lt;methodName&gt;  where methodName is any method on
     *                   grpc ManagedChannelBuilder.  If more than one argument to the method is needed then the
     *                   parameters need to be supplied in an array of Objects.
     *                   </li>
     *                   <li>
     *                   ordererWaitTimeMilliSecs Time to wait in milliseconds for the
     *                   Consenter to accept requests before timing out. The default is two seconds.
     *                   </li>
     *                   </ul>
     * @return The orderer.
     * @throws InvalidArgumentException
     */

    public Consenter newConsenter(String name, String grpcURL, Properties properties) throws InvalidArgumentException {
        clientCheck();
        return Consenter.createNewInstance(name, grpcURL, properties);
    }

    /**
     * Query the channels for peers
     *
     * @param peer the peer to query
     * @return A set of strings with the peer names.
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public Set<String> queryGroups(Node peer) throws InvalidArgumentException, ProposalException {

        clientCheck();

        if (null == peer) {

            throw new InvalidArgumentException("peer set to null");

        }

        //Run this on a system channel.

        try {
            Group systemGroup = Group.newSystemGroup(this);

            return systemGroup.queryGroups(peer);
        } catch (InvalidArgumentException e) {
            throw e; //dont log
        } catch (ProposalException e) {
            logger.error(format("queryGroups for peer %s failed." + e.getMessage(), peer.getName()), e);
            throw e;
        }

    }

    /**
     * Query the peer for installed chaincode information
     *
     * @param peer The peer to query.
     * @return List of SmartContractInfo on installed chaincode @see {@link SmartContractInfo}
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public List<SmartContractInfo> queryInstalledSmartContracts(Node peer) throws InvalidArgumentException, ProposalException {

        clientCheck();

        if (null == peer) {

            throw new InvalidArgumentException("peer set to null");

        }

        try {
            //Run this on a system channel.

            Group systemGroup = Group.newSystemGroup(this);

            return systemGroup.queryInstalledSmartContracts(peer);
        } catch (ProposalException e) {
            logger.error(format("queryInstalledSmartContracts for peer %s failed." + e.getMessage(), peer.getName()), e);
            throw e;
        }

    }

    /**
     * Get signature for group configuration
     *　得到群组配置的签名,通过group对象来调用
     * @param channelConfiguration
     * @param signer
     * @return byte array with the signature
     * @throws InvalidArgumentException
     */

    public byte[] getGroupConfigurationSignature(GroupConfiguration channelConfiguration, User signer)
            throws InvalidArgumentException {
    	//群组配置文件为空则签名也空
    	if ( channelConfiguration==null ) {
    		return null;
    	}
        clientCheck();

        Group systemGroup = Group.newSystemGroup(this);
        return systemGroup.getGroupConfigurationSignature(channelConfiguration, signer);

    }

    /**
     * Get signature for update channel configuration
     * 获取更新通道配置的签名
     * @param updateGroupConfiguration
     * @param signer
     * @return byte array with the signature
     * @throws InvalidArgumentException
     */

    public byte[] getUpdateGroupConfigurationSignature(UpdateGroupConfiguration updateGroupConfiguration,
            User signer) throws InvalidArgumentException {

        clientCheck();

        Group systemGroup = Group.newSystemGroup(this);
        return systemGroup.getUpdateGroupConfigurationSignature(updateGroupConfiguration, signer);

    }

    /**
     * Send install chaincode request proposal to peers.
     *
     * @param installProposalRequest
     * @param peers                  Collection of peers to install on.
     * @return responses from peers.
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<ProposalResponse> sendInstallProposal(InstallProposalRequest installProposalRequest,
            Collection<Node> peers) throws ProposalException, InvalidArgumentException {

        clientCheck();

        installProposalRequest.setSubmitted();
        Group systemGroup = Group.newSystemGroup(this);

        return systemGroup.sendInstallProposal(installProposalRequest, peers);

    }


    private void clientCheck() throws InvalidArgumentException {

        if (null == cryptoSuite) {
            throw new InvalidArgumentException("No cryptoSuite has been set.");
        }

        userContextCheck(userContext);

    }

    void removeGroup(Group channel) {
        synchronized (channels) {
            final String name = channel.getName();
            if (channels.get(name) == channel) { // Only remove if it's the same instance.
                channels.remove(name);
            }
        }
    }
}
