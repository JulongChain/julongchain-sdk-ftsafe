/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.bcia.javachain.sdk.security;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Properties;

import org.bcia.javachain.sdk.exception.CryptoException;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.security.gm.GmCryptoSuiteFactory;
import org.bcia.javachain.common.exception.JavaChainException;

/**
 * All packages for PKI key creation/signing/verification implement this interface
 */
public interface CryptoSuite {

    /**
     * Get Crypto Suite Factory for this implementation.
     *
     * @return MUST return the one and only one instance of a factory that produced this crypto suite.
     */

    CryptoSuiteFactory getCryptoSuiteFactory();

//    /**
//     * @return the {@link Properties} object containing implementation specific key generation properties
//     */
//    Properties getProperties();

    /**
     * Sign the specified byte string.
     *
     * @param plainText the byte string to sign
     * @return the signed data.
     * @throws CryptoException
     */
    //byte[] sign(PrivateKey key, byte[] plainText) throws CryptoException;
    byte[] sign(byte[] plainText) throws CryptoException;

    /**
     * Verify the specified signature
     *
     * @param certificate        the certificate of the signer as the contents of the PEM file
     * @param signature          the signature to verify
     * @param plainText          the original text that is to be verified
     * @return {@code true} if the signature is successfully verified; otherwise {@code false}.
     * @throws CryptoException
     */
    boolean verify(byte[] certificate, byte[] signature, byte[] plainText) throws CryptoException, JavaChainException;

    /**
     * Hash the specified text byte data.
     *
     * @param plainText the text to hash
     * @return the hashed data.
     */
    byte[] hash(byte[] plainText);

    /**
     * The CryptoSuite factory. Currently {@link #getCryptoSuite} will always
     * give you a {@link CryptoPrimitives} object
     */

    class Factory {
        private Factory() {

        }

        /**
         * Get a crypto suite with the default factory with default settings.
         * Settings which can define such parameters such as curve strength, are specific to the crypto factory.
         *
         * @return Default crypto suite.
         * @throws IllegalAccessException
         * @throws InstantiationException
         * @throws ClassNotFoundException
         * @throws CryptoException
         * @throws InvalidArgumentException
         * @throws NoSuchMethodException
         * @throws InvocationTargetException
         */

        public static CryptoSuite getCryptoSuite() throws IllegalAccessException, InstantiationException,
                ClassNotFoundException, CryptoException, InvalidArgumentException, NoSuchMethodException,
                InvocationTargetException {
            return GmCryptoSuiteFactory.getDefault().getCryptoSuite();
        }

        /**
         * Get a crypto suite with the default factory with settings defined by properties
         * Properties are uniquely defined by the specific crypto factory.
         *
         * @param properties properties that define suite characteristics such as strength, curve, hashing .
         * @return
         * @throws IllegalAccessException
         * @throws InstantiationException
         * @throws ClassNotFoundException
         * @throws CryptoException
         * @throws InvalidArgumentException
         * @throws NoSuchMethodException
         * @throws InvocationTargetException
         */
        public static CryptoSuite getCryptoSuite(Properties properties) throws IllegalAccessException, InstantiationException,
                ClassNotFoundException, CryptoException, InvalidArgumentException, NoSuchMethodException,
                InvocationTargetException {
            return CryptoSuiteFactory.getDefault().getCryptoSuite(properties);
        }

    }

    //################################################################################################################################################################################

    /**
     * init初始化方法，从实现体提取到接口
     * @throws CryptoException
     * @throws InvalidArgumentException
     */
    public void init() throws CryptoException, InvalidArgumentException;
    
//    /**
//     * 增加证书到指定位置文件
//     * @param caCertPem
//     * @param alias
//     * @throws CryptoException
//     * @throws InvalidArgumentException
//     */
//    public void addCACertificateToTrustStore(File caCertPem, String alias) throws CryptoException, InvalidArgumentException;
    
//    /**
//     * 增加证书到指定byte数组
//     *
//     * @param caCertPem an X.509 certificate in PEM format
//     * @param alias     an alias associated with the certificate. Used as shorthand for the certificate during crypto operations
//     * @throws CryptoException
//     * @throws InvalidArgumentException
//     */
//    public void addCACertificateToTrustStore(byte[] bytes, String alias) throws CryptoException, InvalidArgumentException;
    
//    /**
//     * getTrustStore returns the KeyStore object where we keep trusted certificates.
//     * If no trust store has been set, this method will create one.
//     *
//     * @return the trust store as a java.security.KeyStore object
//     * @throws CryptoException
//     * @see KeyStore
//     */
//    public KeyStore getTrustStore() throws CryptoException;
}
