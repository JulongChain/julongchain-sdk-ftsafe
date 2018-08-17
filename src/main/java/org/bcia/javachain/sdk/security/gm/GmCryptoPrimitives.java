package org.bcia.javachain.sdk.security.gm;

import static java.lang.String.format;
import static org.bcia.javachain.sdk.helper.Utils.isNullOrEmpty;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;

import org.bcia.javachain.sdk.helper.MspStore;
import org.bcia.javachain.common.exception.VerifyException;
import org.bcia.javachain.common.localmsp.ILocalSigner;
import org.bcia.javachain.common.localmsp.impl.LocalSigner;
import org.bcia.javachain.sdk.security.csp.gm.dxct.sm2.SM2PublicKeyImportOpts;
import org.bcia.javachain.sdk.security.csp.gm.dxct.sm2.SM2SignerOpts;
import org.bcia.javachain.sdk.security.csp.intfs.IKey;
import org.bouncycastle.asn1.x509.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bcia.javachain.sdk.exception.CryptoException;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.helper.Config;
import org.bcia.javachain.sdk.helper.DiagnosticFileDumper;
import org.bcia.javachain.sdk.security.CryptoSuite;
import org.bcia.javachain.sdk.security.CryptoSuiteFactory;
import org.bcia.javachain.common.exception.JavaChainException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;


/**
 * 国密算法实现
 *
 * @author wangzhe
 * @date 2018/5/20
 * @company feitian
 */
public class GmCryptoPrimitives implements CryptoSuite {
    private static final Log logger = LogFactory.getLog(GmCryptoPrimitives.class);

    public GmCryptoPrimitives() {

    }

    /**
     * 验证签名
     * @param pemCertificate 证书pem
     * @param signature 签名值
     * @param plainText 原文
     */
    @Override
    public boolean verify(byte[] pemCertificate, byte[] signature, byte[] plainText) throws CryptoException, JavaChainException {
    	if (plainText == null || signature == null || pemCertificate == null) {
            return false;
        }
    	
        Certificate certificate = CertificateUtils.bytesToX509Certificate(pemCertificate);
    	return verify(certificate, signature, plainText);
    }

    /**
     * 验证签名
     * @param certificate 证书
     * @param signature 签名值
     * @param plainText 原文
     */
    public boolean verify(Certificate certificate, byte[] signature, byte[] plainText) throws CryptoException {
        boolean isVerified = false;

        if (plainText == null || signature == null || certificate == null) {
            return false;
        }

        boolean verify = false;
        Certificate cert = null;
        IKey certPubK = null;
        try {
            cert = CertificateUtils.bytesToX509Certificate(MspStore.getInstance().getSignCerts().get(0));
            byte[] pbBytes = cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
            certPubK = MspStore.getInstance().getCsp().keyImport(pbBytes, new SM2PublicKeyImportOpts(true));
            verify = MspStore.getInstance().getCsp().verify(certPubK, signature, plainText, new SM2SignerOpts());
            if (verify == false) {
                throw new VerifyException("Veify the sign is fail");
            }
        } catch (JavaChainException e) {
            e.printStackTrace();
        }
        return isVerified;
    } // verify

    /**
     * 签名
     * @parma data 数据
     * @throws ClassCastException if the supplied private key is not of type {@link ECPrivateKey}.
     */
    @Override
    public byte[] sign(byte[] data) throws CryptoException {
        ILocalSigner signer = new LocalSigner();
        return signer.sign(data);
    }

    /**
     * 哈希
     */
    @Override
    public byte[] hash(byte[] input) {
        Digest digest = getHashDigest();
        byte[] retValue = new byte[digest.getDigestSize()];
        digest.update(input, 0, input.length);
        digest.doFinal(retValue, 0);
        return retValue;
    }

    @Override
    public void init() throws CryptoException, InvalidArgumentException {

    }

    /**
     * 得到工厂
     */
    @Override
    public CryptoSuiteFactory getCryptoSuiteFactory() {
        return GmHLSDKJCryptoSuiteFactory.instance(); //Factory for this crypto suite.
    }

    final AtomicBoolean inited = new AtomicBoolean(false);


    private Digest getHashDigest() {
        return new SM3Digest();
    }
}
