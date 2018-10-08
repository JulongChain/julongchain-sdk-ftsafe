package org.bcia.javachain.sdk.security.gm;


import static java.lang.String.format;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;
import org.bcia.javachain.common.exception.JavaChainException;

import org.bcia.javachain.sdk.common.log.JavaChainLog;
import org.bcia.javachain.sdk.common.log.JavaChainLogFactory;
import org.bcia.javachain.sdk.security.csp.factory.CspManager;
import org.bcia.javachain.sdk.security.csp.gm.dxct.sm2.SM2PrivateKeyImportOpts;
import org.bcia.javachain.sdk.security.csp.intfs.IKey;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import sun.misc.BASE64Decoder;
import sun.security.util.Debug;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

/**
 * 证书工具类
 * @author wangzhe
 * @date 2018/06/21
 * @company Feitian
 */
public class CertificateUtils {

    private static JavaChainLog log = JavaChainLogFactory.getLog(CertificateUtils.class);
    private static final int ASN1_SEQUENCE = 0x30;
    /**
     *
     * @return
     */
    public static String certificateP12ToPEM() {
        throw new RuntimeException("unsupportted");
    }

    /**
     *
     * @return
     */
    public static String certificateCerToPEM() {
        throw new RuntimeException("unsupportted");
    }

    /**
     * 私钥转PEM
     * @param privateKey
     * @return
     * @throws IOException
     */
    public static String privateKeyObjToPEM(PrivateKey privateKey) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(pemStrWriter);
        pemWriter.writeObject(privateKey);
        pemWriter.close();
        return pemStrWriter.toString();
    }

    /**
     * 证书 变 der
     * @param certificatePEM
     * @return
     * @throws IOException
     */
    public byte[] certificatePEMToDER(String certificatePEM) throws IOException {
        byte[] content = null;
        try (PemReader pemReader = new PemReader(new StringReader(certificatePEM))) {
            final PemObject pemObject = pemReader.readPemObject();
            content = pemObject.getContent();
        } catch (IOException e) {
            throw e;
        }
        return content;
    }





    /**
     * 暂时用不上 TODO 国密也不支持
     * @param path
     * @param password
     * @return
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws KeyStoreException
     */
    public static KeyStore jksToKeyStore(String path, String password) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType(), BouncyCastleProvider.class.newInstance());
            keyStore.load(CertificateUtils.class.getResourceAsStream(path), password.toCharArray());
            return keyStore;
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return null;
    }

//	/**
//	 * 字符串转bytes
//	 * @param type 字符串类型
//	 * @param str 字符串
//	 * @return
//	 */
//	public byte[] bytesFromString(String type, String str) {
//		if ( type.equals("pem") ) {
//			try {
//				return str.getBytes("utf-8");
//			} catch (UnsupportedEncodingException e) {
//				return null;
//			}
//		} else if ( type.equals("base64") ) {
//			return DatatypeConverter.parseBase64Binary(str);
//		} else if ( type.equals("hex") ) {
//			return DatatypeConverter.parseHexBinary(str);
//		} else {
//			throw new RuntimeException("not support!");
//		}
//	}

    /**
     * 字节转私钥对象
     * @param pemKey pem-encoded private key
     * @return
     */
    public static IKey bytesToPrivateKey(byte[] pemKey) throws JavaChainException {
        try {
            InputStreamReader reader = new InputStreamReader(new ByteArrayInputStream(pemKey));
            PemReader pemReader = new PemReader(reader);
            PemObject pemObject = pemReader.readPemObject();
            reader.close();

            byte[] encodedData = pemObject.getContent();
            List<Object> list = decodePrivateKeyPKCS8(encodedData);
            Object rawKey = list.get(1);
            return CspManager.getDefaultCsp().keyImport(rawKey, new SM2PrivateKeyImportOpts(true));
        } catch (Exception e) {
            log.error("An error occurred on importPrivateKey: {}", e.getMessage());
        }
        return null;
    }

    private static List<Object> decodePrivateKeyPKCS8(byte[] encodedData) throws JavaChainException {
        try {
            DerValue derValue = new DerValue(new ByteArrayInputStream(encodedData));
            if (derValue.tag != ASN1_SEQUENCE) {
                throw new JavaChainException("invalid key format");
            } else {
                BigInteger version = derValue.data.getBigInteger();
                if (!version.equals(BigInteger.ZERO)) {
                    throw new JavaChainException("version mismatch: (supported: " + Debug.toHexString(BigInteger.ZERO) + ", parsed: " + Debug.toHexString(version));
                } else {
                    AlgorithmId algId = AlgorithmId.parse(derValue.data.getDerValue());
                    byte[] rawPrivateKey = derValue.data.getOctetString();
                    List<Object> list = new ArrayList<>();
                    list.add(algId);
                    list.add(rawPrivateKey);
                    return list;
                }
            }
        } catch (IOException e) {
            throw new JavaChainException("IOException : " + e.getMessage());
        }
    }

//    /**
//     * 字节转私钥对象
//     * @param pemKey pem-encoded private key
//     * @return
//     */
//    public static PrivateKey bytesToPrivateKey(byte[] pemKey) {
//        PrivateKey pk = null;
//
//        try {
//            PemReader pr = new PemReader(new StringReader(new String(pemKey)));
//            PemObject po = pr.readPemObject();
//            PEMParser pem = new PEMParser(new StringReader(new String(pemKey)));
//            logger.info("found private key with type " + po.getType());
//            if (po.getType().equals("EC PRIVATE KEY")) {
                //直接是privatekey
//                pk = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) pem.readObject());
//            } else {
                //是keypair
//                PEMKeyPair kp = (PEMKeyPair) pem.readObject();
//                pk = new JcaPEMKeyConverter().getPrivateKey(kp.getPrivateKeyInfo());
            	/*
            	PEMKeyPair kp = (PEMKeyPair) pem.readObject();
            	PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(kp.getPrivateKeyInfo().getEncoded());
                PrivateKeyInfo info = PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded());
                pk = BouncyCastleProvider.getPrivateKey(info);
	            */
//            }
//            logger.info(pk.toString());
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return pk;
//    }





    //私钥字符串转对象
    public static PrivateKey getPrivateKey(String privateKey) throws Exception{
        StringReader in=new StringReader(privateKey);
        String tmp = "";
        BufferedReader bf = new BufferedReader(in);
        String b = bf.readLine();

        KeyFactory keyf = null;
        if(b!= null && b.indexOf("---") != -1 && b.indexOf("EC") != -1) {
            keyf = KeyFactory.getInstance("EC");
        }else if(b!= null && b.indexOf("---") != -1 && b.indexOf("RSA") != -1) {
            keyf = KeyFactory.getInstance("RSA");
        }else{
            System.out.println("私钥格式异常!");
            return null;
        }
        privateKey = replaceHeadAndEnd(privateKey);
        PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(new Base64().decode(privateKey) );
        PrivateKey priKey = keyf.generatePrivate(priPKCS8);
        return priKey;
    }


    private static String replaceHeadAndEnd(String content) throws Exception{
        StringReader in=new StringReader(content);
        String tmp = "";
        BufferedReader bf = new BufferedReader(in);
        String b;
        while((b= bf.readLine())!= null){
            if(b.indexOf("-----") == -1){
                tmp += b;
            }
        }
        return tmp;
    }


    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        KeyFactory keyf = null;
        if(key != null && key.indexOf("EC") != -1)
            keyf = KeyFactory.getInstance("EC");
        else if(key != null && key.indexOf("RSA") != -1)
            keyf = KeyFactory.getInstance("RSA");
        else{
            System.out.println("私钥格式异常!");
            return null;
        }
        key = replaceHeadAndEnd(key);
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey publicKey = keyf.generatePublic(keySpec);
        return publicKey;
    }



    public static PublicKey bytesToPublicKey(byte[] pemKey) {
        PublicKey pk = null;

        try {
            PemReader pr = new PemReader(new StringReader(new String(pemKey)));
            PemObject po = pr.readPemObject();
            PEMParser pem = new PEMParser(new StringReader(new String(pemKey)));
//            logger.info("found private key with type " + po.getType());
            if (po.getType().equals("PUBLIC KEY")) {
                pk = new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) pem.readObject());
            } else {
                //是keypair
                PEMKeyPair kp = (PEMKeyPair) pem.readObject();
                pk = new JcaPEMKeyConverter().getPublicKey(kp.getPublicKeyInfo());

            }
//            logger.info(pk.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pk;
    }


    /**
     * cer格式文件转证书对象
     * @param bis 流
     * @param decodeBase64 是否base64解码
     */
    public static Certificate cerFileToX509Certificate(InputStream bis, boolean decodeBase64) {
        InputStream ins = null;
        try {
            if ( decodeBase64 ) {
                ins = base64Decode(bis);
            } else {
                ins = bis;
            }
            //Certificate cert = CertificateFactory.getInstance("X.509", BouncyCastleProvider.class.newInstance()).generateCertificate(ins);
            Certificate cert = Certificate.getInstance(new PemReader(new InputStreamReader(ins)).readPemObject().getContent());
            log.info(cert.toString());
            return cert;
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                bis.close();
            } catch (Exception e) {
            }
            try {
                ins.close();
            } catch (Exception e) {
            }
        }
        return null;
    }

    /**
     * 字节码转证书对象
     * @param pemCertificate
     * @return
     * @throws JavaChainException
     */
    public static Certificate bytesToX509Certificate(byte[] pemCertificate) throws JavaChainException {
        Certificate ret = null;
        JavaChainException rete = null;

        List<Provider> providerList = new LinkedList<>(Arrays.asList(Security.getProviders()));
        try {
            providerList.add(BouncyCastleProvider.class.newInstance());
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        for (Provider provider : providerList) {
            try {
                if (null == provider) {
                    continue;
                }
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509", provider);
                if (null != certFactory) {

                    //   BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(pemCertificate));
                    //Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(pemCertificate));
                    Certificate certificate = Certificate.getInstance(new PemReader(new InputStreamReader(new ByteArrayInputStream(pemCertificate))).readPemObject().getContent());
                    if (certificate instanceof Certificate) {
                        ret = (Certificate) certificate;
                        rete = null;
                        break;
                    }

                }
            } catch (Exception e) {

                rete = new JavaChainException(e.getMessage(), e);

            }

        }

        if (null != rete) {

            throw rete;

        }

        if (ret == null) {
            log.error("Could not convert pem bytes");
        }

        return ret;

    }

    /**
     * Sign data with the specified elliptic curve private key.
     *
     * @param privateKey elliptic curve private key.
     * @param data       data to sign
     * @return the signed data.
     * @throws JavaChainException
     */
    public static byte[] sign(ECPrivateKey privateKey, byte[] data, String curveName, String algorithm, Provider provider) throws JavaChainException {
        try {
            X9ECParameters params = ECNamedCurveTable.getByName(curveName);
            BigInteger curveN = params.getN();

            Signature sig = Signature.getInstance(algorithm, provider);
            sig.initSign(privateKey);
            sig.update(data);
            byte[] signature = sig.sign();

            BigInteger[] sigs = decodeECDSASignature(signature);

            sigs = preventMalleability(sigs, curveN);

            ByteArrayOutputStream s = new ByteArrayOutputStream();

            DERSequenceGenerator seq = new DERSequenceGenerator(s);
            seq.addObject(new ASN1Integer(sigs[0]));
            seq.addObject(new ASN1Integer(sigs[1]));
            seq.close();
            return s.toByteArray();

        } catch (Exception e) {
            e.printStackTrace();
            throw new JavaChainException("Could not sign the message using private key", e);
        }
    }

    /**
     * Decodes an ECDSA signature and returns a two element BigInteger array.
     * 解码ECDSA签名并返回两个元素BigInteger数组。
     * @param signature ECDSA signature bytes.
     * @return BigInteger array for the signature's r and s values
     * @throws Exception
     */
    private static BigInteger[] decodeECDSASignature(byte[] signature) throws Exception {
        ByteArrayInputStream inStream = new ByteArrayInputStream(signature);
        ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
        ASN1Primitive asn1 = asnInputStream.readObject();

        BigInteger[] sigs = new BigInteger[2];
        int count = 0;
        if (asn1 instanceof ASN1Sequence) {
            ASN1Sequence asn1Sequence = (ASN1Sequence) asn1;
            ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
            for (ASN1Encodable asn1Encodable : asn1Encodables) {
                ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
                if (asn1Primitive instanceof ASN1Integer) {
                    ASN1Integer asn1Integer = (ASN1Integer) asn1Primitive;
                    BigInteger integer = asn1Integer.getValue();
                    if (count  < 2) {
                        sigs[count] = integer;
                    }
                    count++;
                }
            }
        }
        if (count != 2) {
            throw new JavaChainException(format("Invalid ECDSA signature. Expected count of 2 but got: %d. Signature is: %s", count,
                    DatatypeConverter.printHexBinary(signature)));
        }
        return sigs;
    }

    /**
     * 阻止可塑性？！（没理解）
     * @param sigs 两个整数数组
     * @param curveN 曲线
     * @return
     */
    private static BigInteger[] preventMalleability(BigInteger[] sigs, BigInteger curveN) {
        BigInteger cmpVal = curveN.divide(BigInteger.valueOf(2L));
        BigInteger sval = sigs[1];
        //第二个整数比曲线/2数大
        if (sval.compareTo(cmpVal) == 1) {
            //第二个整数等于曲线减去第二个整数
            sigs[1] = curveN.subtract(sval);
        }
        return sigs;
    }

    /**
     * 流base64解码
     * @param ins
     * @return
     * @throws Exception
     */
    public static InputStream base64Decode(InputStream ins) throws Exception {
        byte[] bytes = new byte[ins.available()];
        byte[] decodeBytes = null;
        try {
            ins.read(bytes);
            decodeBytes = new Base64().decode(bytes);
            return new ByteArrayInputStream(decodeBytes);
        } catch(Exception e) {
            e.printStackTrace();
            throw e;
        } finally {
            ins.close();
        }
    }

    /**
     * 证书 变 der
     * @param certificatePEM
     * @return
     */
    public static byte[] certificateToDER(String certificatePEM) {

        byte[] content = null;

        try (PemReader pemReader = new PemReader(new StringReader(certificatePEM))) {
            final PemObject pemObject = pemReader.readPemObject();
            content = pemObject.getContent();

        } catch (IOException e) {
            // best attempt
        }

        return content;
    }
}
