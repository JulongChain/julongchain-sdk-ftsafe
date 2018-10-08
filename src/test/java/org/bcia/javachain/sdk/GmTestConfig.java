/*
 *  Copyright 2016, 2017 IBM, DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.bcia.javachain.sdk;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Level;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mvel2.MVEL;
import org.yaml.snakeyaml.Yaml;

/**
 * Config allows for a global config of the toolkit. Central location for all
 * toolkit configuration defaults. Has a local config file that can override any
 * property defaults. Config file can be relocated via a system property
 * "org.bcia.javachain.sdk.configuration". Any property can be overridden
 * with environment variable and then overridden
 * with a java system property. Property hierarchy goes System property
 * overrides environment variable which overrides config file for default values specified here.
 * 
 * modified for Node,SmartContract,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */

public class GmTestConfig {
    private static final Log logger = LogFactory.getLog(GmTestConfig.class);

    public static final String ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION = "org.bcia.javachain.sdk.configuration";
    /**
     * Timeout settings
     **/
    public static final String PROPOSAL_WAIT_TIME = "org.bcia.javachain.sdk.proposal.wait.time";
    public static final String CHANNEL_CONFIG_WAIT_TIME = "org.bcia.javachain.sdk.channelconfig.wait_time";
    public static final String TRANSACTION_CLEANUP_UP_TIMEOUT_WAIT_TIME = "org.bcia.javachain.sdk.client.transaction_cleanup_up_timeout_wait_time";
    public static final String ORDERER_RETRY_WAIT_TIME = "org.bcia.javachain.sdk.orderer_retry.wait_time";
    public static final String ORDERER_WAIT_TIME = "org.bcia.javachain.sdk.orderer.ordererWaitTimeMilliSecs";
    public static final String PEER_EVENT_REGISTRATION_WAIT_TIME = "org.bcia.javachain.sdk.peer.eventRegistration.wait_time";
    public static final String PEER_EVENT_RETRY_WAIT_TIME = "org.bcia.javachain.sdk.peer.retry_wait_time";
    public static final String EVENTHUB_CONNECTION_WAIT_TIME = "org.bcia.javachain.sdk.eventhub_connection.wait_time";
    public static final String GENESISBLOCK_WAIT_TIME = "org.bcia.javachain.sdk.channel.genesisblock_wait_time";
    /**
     * Crypto configuration settings
     **/
    public static final String DEFAULT_CRYPTO_SUITE_FACTORY = "org.bcia.javachain.sdk.crypto.default_crypto_suite_factory";
    public static final String SECURITY_LEVEL = "org.bcia.javachain.sdk.security_level";
    public static final String SECURITY_PROVIDER_CLASS_NAME = "org.bcia.javachain.sdk.security_provider_class_name";
    public static final String SECURITY_CURVE_MAPPING = "org.bcia.javachain.sdk.security_curve_mapping";
    public static final String HASH_ALGORITHM = "org.bcia.javachain.sdk.hash_algorithm";
    public static final String ASYMMETRIC_KEY_TYPE = "org.bcia.javachain.sdk.crypto.asymmetric_key_type";
    public static final String CERTIFICATE_FORMAT = "org.bcia.javachain.sdk.crypto.certificate_format";
    public static final String SIGNATURE_ALGORITHM = "org.bcia.javachain.sdk.crypto.default_signature_algorithm";
    /**
     * Logging settings
     **/
    public static final String MAX_LOG_STRING_LENGTH = "org.bcia.javachain.sdk.log.stringlengthmax";
    public static final String EXTRALOGLEVEL = "org.bcia.javachain.sdk.log.extraloglevel";  // ORG_HYPERLEDGER_FABRIC_SDK_LOG_EXTRALOGLEVEL
    public static final String LOGGERLEVEL = "org.bcia.javachain.sdk.loglevel";  // ORG_HYPERLEDGER_FABRIC_SDK_LOGLEVEL=TRACE,DEBUG
    public static final String DIAGNOTISTIC_FILE_DIRECTORY = "org.bcia.javachain.sdk.diagnosticFileDir"; //ORG_HYPERLEDGER_FABRIC_SDK_DIAGNOSTICFILEDIR

    /**
     * Miscellaneous settings
     **/
    public static final String PROPOSAL_CONSISTENCY_VALIDATION = "org.bcia.javachain.sdk.proposal.consistency_validation";

    private static GmTestConfig config;
    private static final Properties sdkProperties = new Properties();

    
    private Map<String, String> yamlMap;
    
    
    public String getSimpleValue(String key) {
    	String value = yamlMap.get(key);
    	logger.info("config >> key: "+ key +", value: "+ value);
    	return value;
    }
    
    public String getValue(String key) {
    	String value = (String) MVEL.eval(key, yamlMap);
    	logger.info("config >> key: "+ key +", value: "+ value);
    	return value;
    }
    
    private GmTestConfig() {
//        File loadFile;

        try {
//          loadFile = new File(System.getProperty(ORG_BCIA_JAVACHAIN_SDK_CONFIGURATION, DEFAULT_CONFIG))
//          .getAbsoluteFile();
//  logger.debug(format("Loading configuration from %s and it is present: %b", loadFile.toString(),
//          loadFile.exists()));
//  configProps = new FileInputStream(loadFile);
            yamlMap = (LinkedHashMap<String, String>) new Yaml().load(this.getClass().getResourceAsStream("/test_config.yaml"));
        } catch (Exception e) {
        	e.printStackTrace();
        } finally {
            // Default values
            /**
             * Timeout settings
             **/
            defaultProperty(PROPOSAL_WAIT_TIME, "20000");
            defaultProperty(CHANNEL_CONFIG_WAIT_TIME, "15000");
            defaultProperty(ORDERER_RETRY_WAIT_TIME, "200");
            // defaultProperty(ORDERER_WAIT_TIME, "10000");
            defaultProperty(ORDERER_WAIT_TIME, "30000");
            defaultProperty(PEER_EVENT_REGISTRATION_WAIT_TIME, "5000");
            defaultProperty(PEER_EVENT_RETRY_WAIT_TIME, "500");
            defaultProperty(EVENTHUB_CONNECTION_WAIT_TIME, "1000");
            defaultProperty(GENESISBLOCK_WAIT_TIME, "5000");
            /**
             * This will NOT complete any transaction futures time out and must be kept WELL above any expected future timeout
             * for transactions sent to the Orderer. For internal cleanup only.
             */

            defaultProperty(TRANSACTION_CLEANUP_UP_TIMEOUT_WAIT_TIME, "600000"); //10 min.

            /**
             * Crypto configuration settings
             **/
            /*
            defaultProperty(DEFAULT_CRYPTO_SUITE_FACTORY, "org.bcia.javachain.sdk.security.HLSDKJCryptoSuiteFactory");
            defaultProperty(SECURITY_LEVEL, "256");
            defaultProperty(SECURITY_PROVIDER_CLASS_NAME, BouncyCastleProvider.class.getName());
            defaultProperty(SECURITY_CURVE_MAPPING, "256=secp256r1:384=secp384r1");
            defaultProperty(HASH_ALGORITHM, "SHA2");
            defaultProperty(ASYMMETRIC_KEY_TYPE, "EC");
            defaultProperty(CERTIFICATE_FORMAT, "X.509");
            defaultProperty(SIGNATURE_ALGORITHM, "SHA256withECDSA");
            */
            
            defaultProperty(DEFAULT_CRYPTO_SUITE_FACTORY, "org.bcia.javachain.sdk.security.gm.GmHLSDKJCryptoSuiteFactory");//wangzhe
            defaultProperty(SECURITY_LEVEL, "256");
            defaultProperty(SECURITY_PROVIDER_CLASS_NAME, BouncyCastleProvider.class.getName());
            defaultProperty(SECURITY_CURVE_MAPPING, "256=sm2p256v1");
            defaultProperty(HASH_ALGORITHM, "SM3");//SHA2
            defaultProperty(ASYMMETRIC_KEY_TYPE, "EC");
            defaultProperty(CERTIFICATE_FORMAT, "X.509");
            defaultProperty(SIGNATURE_ALGORITHM, "SM3withSM2");

            /**
             * Logging settings
             **/
            defaultProperty(MAX_LOG_STRING_LENGTH, "64");
            defaultProperty(EXTRALOGLEVEL, "0");
            defaultProperty(LOGGERLEVEL, null);
            defaultProperty(DIAGNOTISTIC_FILE_DIRECTORY, null);
            /**
             * Miscellaneous settings
             */
            defaultProperty(PROPOSAL_CONSISTENCY_VALIDATION, "true");

            final String inLogLevel = sdkProperties.getProperty(LOGGERLEVEL);

            if (null != inLogLevel) {

                Level setTo;

                switch (inLogLevel.toUpperCase()) {

                    case "TRACE":
                        setTo = Level.TRACE;
                        break;

                    case "DEBUG":
                        setTo = Level.DEBUG;
                        break;

                    case "INFO":
                        setTo = Level.INFO;
                        break;

                    case "WARN":
                        setTo = Level.WARN;
                        break;

                    case "ERROR":
                        setTo = Level.ERROR;
                        break;

                    default:
                        setTo = Level.INFO;
                        break;

                }

                if (null != setTo) {
                    org.apache.log4j.Logger.getLogger("org.bcia.javachain").setLevel(setTo);
                }

            }

        }

    }

    /**
     * getConfig return back singleton for SDK configuration.
     *
     * @return Global configuration
     */
    public static GmTestConfig getConfig() {
        if (null == config) {
            config = new GmTestConfig();
        }
        return config;

    }

    /**
     * getProperty return back property for the given value.
     *
     * @param property
     * @return String value for the property
     */
    private String getProperty(String property) {

        String ret = sdkProperties.getProperty(property);

        if (null == ret) {
            logger.warn(format("No configuration value found for '%s'", property));
        }
        return ret;
    }

    private static void defaultProperty(String key, String value) {

        String ret = System.getProperty(key);
        if (ret != null) {
            sdkProperties.put(key, ret);
        } else {
            String envKey = key.toUpperCase().replaceAll("\\.", "_");
            ret = System.getenv(envKey);
            if (null != ret) {
                sdkProperties.put(key, ret);
            } else {
                if (null == sdkProperties.getProperty(key) && value != null) {
                    sdkProperties.put(key, value);
                }

            }

        }
    }

    /**
     * Get the configured security level. The value determines the elliptic curve used to generate keys.
     *
     * @return the security level.
     */
    public int getSecurityLevel() {

        return Integer.parseInt(getProperty(SECURITY_LEVEL));

    }

    /**
     * Get the configured security provider.
     * This is the security provider used for the default SDK crypto suite factory.
     *
     * @return the security provider.
     */
    public String getSecurityProviderClassName() {
        return getProperty(SECURITY_PROVIDER_CLASS_NAME);
    }

    /**
     * Get the name of the configured hash algorithm, used for digital signatures.
     *
     * @return the hash algorithm name.
     */
    public String getHashAlgorithm() {
        return getProperty(HASH_ALGORITHM);

    }

    private Map<Integer, String> curveMapping = null;

    /**
     * Get a mapping from strength to curve desired.
     *
     * @return mapping from strength to curve name to use.
     */
    public Map<Integer, String> getSecurityCurveMapping() {

        if (curveMapping == null) {

            curveMapping = parseSecurityCurveMappings(getProperty(SECURITY_CURVE_MAPPING));
        }

        return Collections.unmodifiableMap(curveMapping);
    }

    public static Map<Integer, String> parseSecurityCurveMappings(final String property) {
        Map<Integer, String> lcurveMapping = new HashMap<>(8);

        if (property != null && !property.isEmpty()) { //empty will be caught later.

            String[] cmaps = property.split("[ \t]*:[ \t]*");
            for (String mape : cmaps) {

                String[] ep = mape.split("[ \t]*=[ \t]*");
                if (ep.length != 2) {
                    logger.warn(format("Bad curve mapping for %s in property %s", mape, SECURITY_CURVE_MAPPING));
                    continue;
                }

                try {
                    int parseInt = Integer.parseInt(ep[0]);
                    lcurveMapping.put(parseInt, ep[1]);
                } catch (NumberFormatException e) {
                    logger.warn(format("Bad curve mapping. Integer needed for strength %s for %s in property %s",
                            ep[0], mape, SECURITY_CURVE_MAPPING));
                }

            }

        }
        return lcurveMapping;
    }

    /**
     * Get the timeout for a single proposal request to endorser.
     *　得到提案等待时间
     * @return the timeout in milliseconds.
     */
    public long getProposalWaitTime() {
        return Long.parseLong(getProperty(PROPOSAL_WAIT_TIME));
    }

    /**
     * Get the configured time to wait for genesis block.
     *　得到创世区块等待时间
     * @return time in milliseconds.
     */
    public long getGenesisBlockWaitTime() {
        return Long.parseLong(getProperty(GENESISBLOCK_WAIT_TIME));
    }

    /**
     * Time to wait for channel to be configured.
     *　组等待时间
     * @return
     */
    public long getGroupConfigWaitTime() {
        return Long.parseLong(getProperty(CHANNEL_CONFIG_WAIT_TIME));
    }

    /**
     * Time to wait before retrying an operation.
     *　排序重试等待时间
     * @return
     */
    public long getConsenterRetryWaitTime() {
        return Long.parseLong(getProperty(ORDERER_RETRY_WAIT_TIME));
    }

    public long getConsenterWaitTime() {
        return Long.parseLong(getProperty(ORDERER_WAIT_TIME));
    }

    /**
     * getNodeEventRegistrationWaitTime
     *
     * @return time in milliseconds to wait for peer eventing service to wait for event registration
     */
    public long getNodeEventRegistrationWaitTime() {
        return Long.parseLong(getProperty(PEER_EVENT_REGISTRATION_WAIT_TIME));
    }

    /**
     * getNodeEventRegistrationWaitTime
     *
     * @return time in milliseconds to wait for peer eventing service to wait for event registration
     */
    public  long getNodeRetryWaitTime() {
        return Long.parseLong(getProperty(PEER_EVENT_RETRY_WAIT_TIME));
    }

    public long getEventHubConnectionWaitTime() {
        return Long.parseLong(getProperty(EVENTHUB_CONNECTION_WAIT_TIME));
    }

    public String getAsymmetricKeyType() {
        return getProperty(ASYMMETRIC_KEY_TYPE);
    }

    public String getCertificateFormat() {
        return getProperty(CERTIFICATE_FORMAT);
    }

    public String getSignatureAlgorithm() {
        return getProperty(SIGNATURE_ALGORITHM);
    }

    public String getDefaultCryptoSuiteFactory() {
        return getProperty(DEFAULT_CRYPTO_SUITE_FACTORY);
    }

    public int maxLogStringLength() {
        return Integer.parseInt(getProperty(MAX_LOG_STRING_LENGTH));
    }

    /**
     * getProposalConsistencyValidation determine if validation of the proposals should
     * be done before sending to the orderer.
     *
     * @return if true proposals will be checked they are consistent with each other before sending to the Orderer
     */

    public boolean getProposalConsistencyValidation() {
        return Boolean.parseBoolean(getProperty(PROPOSAL_CONSISTENCY_VALIDATION));

    }

    private int extraLogLevel = -1;

    public boolean extraLogLevel(int val) {
        if (extraLogLevel == -1) {
            extraLogLevel = Integer.parseInt(getProperty(EXTRALOGLEVEL));
        }

        return val <= extraLogLevel;

    }

    /**
     * This does NOT trigger futures time out and must be kept WELL above any expected future timeout
     * for transactions sent to the Orderer
     *
     * @return
     */
    public long getTransactionListenerCleanUpTimeout() {
        return Long.parseLong(getProperty(TRANSACTION_CLEANUP_UP_TIMEOUT_WAIT_TIME));
    }
    
    
    
    
    
    
    private static final Pattern compile = Pattern.compile("^-----BEGIN CERTIFICATE-----$" + "(.*?)" + "\n-----END CERTIFICATE-----\n", Pattern.DOTALL | Pattern.MULTILINE);

    static String getStringCert(String pemFormat) {
        String ret = null;

        final Matcher matcher = compile.matcher(pemFormat);
        if (matcher.matches()) {
        	
            final String base64part = matcher.group(1).replaceAll("\n", "");
            Base64.Decoder b64dec = Base64.getDecoder();
            ret = new String(b64dec.decode(base64part.getBytes(UTF_8)));

        } else {
            System.err.println("Certificate failed to match expected pattern. Certificate:\n" + pemFormat);
        }

        return ret;
    }
    
    /**
     * 得到文件内容字节数组
     * @param filePath 文件路径
     * @return
     * @throws IOException 
     */
    public byte[] getResourceAsBytes(String filePath) throws IOException {
    	BufferedInputStream fis = new BufferedInputStream(this.getClass().getResourceAsStream(filePath));
		try {
			byte[] bytes = new byte[fis.available()];
			fis.read(bytes);
			return bytes;
		} catch (IOException e) {
			e.printStackTrace();
			throw e;
		} finally {
			try {
				fis.close();
			} catch (IOException e) {
			}
		}
    }
    
    public static void main(String[] args) {
//    	String json = "{\n" + 
//				"\"success\": true,\n" + 
//				"\"result\":{\"Cert\":\"-----BEGIN CERTIFICATE-----\nMIIBqDCCAU6gAwIBAgIIe/ffcNHa29MwCgYIKoEcz1UBg3UwJTELMAkGA1UEBhMCQ04xFjAUBgNVBAMMDUJDSUEgU00yIFJPT1QwHhcNMTgwNjE0MDc0MzI1WhcNMjgwNjExMDc0MzI0WjAqMQswCQYDVQQGEwJDTjEbMBkGA1UEAwwSQkNJQSBTTTIgSXNzdWVyIENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEP8QBMyR29tsCCFKNfcrjK/xvWyi0SblCRepmoJUpFgV75f/kyTX6Ch/mXTNQqY3ivYdK9xsxyHyhf4Txt+ZrQ6NjMGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSVUHfWfJi2FR+EG8lqDlE2rCLr+zAdBgNVHQ4EFgQU5N+/MR9HR9idtSYY8Kfbd+5L6MowDgYDVR0PAQH/BAQDAgGGMAoGCCqBHM9VAYN1A0gAMEUCIHRX5rK4/NcOzGQA389mbb0e9W9xbP0VIg6pHdsVC6KiAiEAh15saej0ZKJKkEDwpT1Mv4lGRPe94FUFjQtW5eooSdY=\\n-----END CERTIFICATE-----\\n\"\n" + 
//				"		}\n" + 
//				"}";
//    	
//    	String signedPem = getStringCert("-----BEGIN CERTIFICATE-----\n"+
//    			"MIIBqDCCAU6gAwIBAgIIe/ffcNHa29MwCgYIKoEcz1UBg3UwJTELMAkGA1UEBhMCQ04xFjAUBgNVBAMMDUJDSUEgU00yIFJPT1QwHhcNMTgwNjE0MDc0MzI1WhcNMjgwNjExMDc0MzI0WjAqMQswCQYDVQQGEwJDTjEbMBkGA1UEAwwSQkNJQSBTTTIgSXNzdWVyIENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEP8QBMyR29tsCCFKNfcrjK/xvWyi0SblCRepmoJUpFgV75f/kyTX6Ch/mXTNQqY3ivYdK9xsxyHyhf4Txt+ZrQ6NjMGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSVUHfWfJi2FR+EG8lqDlE2rCLr+zAdBgNVHQ4EFgQU5N+/MR9HR9idtSYY8Kfbd+5L6MowDgYDVR0PAQH/BAQDAgGGMAoGCCqBHM9VAYN1A0gAMEUCIHRX5rK4/NcOzGQA389mbb0e9W9xbP0VIg6pHdsVC6KiAiEAh15saej0ZKJKkEDwpT1Mv4lGRPe94FUFjQtW5eooSdY="+
//    			"\n-----END CERTIFICATE-----\n");
//   	 	System.err.println(signedPem);
   	 	
   	 	
   	 	
   	 	
    	String str = new String(Base64.getEncoder().encode("-----BEGIN CERTIFICATE-----\nMIIBqDCCAU6gAwIBAgIIe/ffcNHa29MwCgYIKoEcz1UBg3UwJTELMAkGA1UEBhMCQ04xFjAUBgNVBAMMDUJDSUEgU00yIFJPT1QwHhcNMTgwNjE0MDc0MzI1WhcNMjgwNjExMDc0MzI0WjAqMQswCQYDVQQGEwJDTjEbMBkGA1UEAwwSQkNJQSBTTTIgSXNzdWVyIENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEP8QBMyR29tsCCFKNfcrjK/xvWyi0SblCRepmoJUpFgV75f/kyTX6Ch/mXTNQqY3ivYdK9xsxyHyhf4Txt+ZrQ6NjMGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSVUHfWfJi2FR+EG8lqDlE2rCLr+zAdBgNVHQ4EFgQU5N+/MR9HR9idtSYY8Kfbd+5L6MowDgYDVR0PAQH/BAQDAgGGMAoGCCqBHM9VAYN1A0gAMEUCIHRX5rK4/NcOzGQA389mbb0e9W9xbP0VIg6pHdsVC6KiAiEAh15saej0ZKJKkEDwpT1Mv4lGRPe94FUFjQtW5eooSdY=\n-----END CERTIFICATE-----\n".getBytes()));
   	 System.out.println(new String(Base64.getDecoder().decode(str.getBytes())));
    }
}