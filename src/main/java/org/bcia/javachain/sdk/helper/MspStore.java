/**
 * Copyright BCIA. All Rights Reserved.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bcia.javachain.sdk.helper;



import com.google.protobuf.ByteString;
import org.apache.commons.io.FileUtils;
import org.bcia.javachain.sdk.security.gm.CertificateUtils;
import org.bcia.julongchain.common.exception.JavaChainException;
import org.bcia.julongchain.common.exception.VerifyException;
import org.bcia.julongchain.common.localmsp.ILocalSigner;
import org.bcia.julongchain.common.localmsp.impl.LocalSigner;
import org.bcia.julongchain.common.log.JavaChainLog;
import org.bcia.julongchain.common.log.JavaChainLogFactory;
import org.bcia.julongchain.common.tools.cryptogen.CspHelper;
import org.bcia.julongchain.csp.gm.dxct.sm2.SM2PublicKeyImportOpts;
import org.bcia.julongchain.csp.gm.dxct.sm2.SM2SignerOpts;
import org.bcia.julongchain.csp.intfs.ICsp;
import org.bcia.julongchain.csp.intfs.IKey;
import org.bcia.julongchain.msp.IIdentity;
import org.bcia.julongchain.msp.entity.IdentityIdentifier;
import org.bcia.julongchain.msp.mgmt.GlobalMspManagement;
import org.bcia.julongchain.msp.mgmt.Identity;
import org.bcia.julongchain.msp.mgmt.Msp;
import org.bcia.julongchain.msp.util.MspConfigBuilder;
import org.bcia.julongchain.protos.msp.Identities;
import org.bcia.julongchain.protos.msp.MspConfigPackage;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Hex;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import java.util.Map;
import java.util.Objects;

import static java.lang.String.format;


/**
 * MspStore 保存了ＭＳＰ相關所有內容
 * 當ｏｒｄｅｒ和ｎｏｄｅ變爲多個的時候在將此類變爲多實力的對象
 *
 * @author wangzhe
 * @date 2018/7/26
 * @company FEITIAN
 */
public class MspStore {

    private static JavaChainLog log = JavaChainLogFactory.getLog(MspStore.class);

    //這幾句是泄私的
    public static String MSP_ID = GlobalMspManagement.getLocalMsp().getIdentifier();
    public static String MSP_DIR = System.getProperty("user.dir") +"/msp/";
    public static String CONFIG_DIR = System.getProperty("user.dir") +"/config/";

    private List<byte[]> caCerts = new ArrayList<>();
    private List<byte[]> adminCerts = new ArrayList<>();
    private List<byte[]> signCerts = new ArrayList<>();
    private List<byte[]> tlsCaCerts = new ArrayList<>();
    private List<byte[]> serverKeys = new ArrayList<>();
    private List<byte[]> clientKeys = new ArrayList<>();
    private List<byte[]> clientCerts = new ArrayList<>();
    private List<byte[]> tlsClientCerts = new ArrayList<>();
    private Map<String, String> configMap;


    public List<byte[]> getCaCerts() {
        return caCerts;
    }

    public List<byte[]> getAdminCerts() {
        return adminCerts;
    }

    public List<byte[]> getSignCerts() {
        return signCerts;
    }

    public List<byte[]> getTlsCaCerts() {
        return tlsCaCerts;
    }

    public List<byte[]> getTlsClientCerts() {
        return tlsClientCerts;
    }

    public Map<String, String> getConfigMap() {
        return configMap;
    }

    public List<byte[]> getServerKeys() {
        return serverKeys;
    }

    public List<byte[]> getClientKeys() { return clientKeys; }

    public List<byte[]> getClientCerts() {
        return clientCerts;
    }

    public Msp getMsp() {
        return msp;
    }

    public static String getMspId() {
        return MSP_ID;
    }


    private static MspStore singleton;
    private Msp msp;

    private MspStore() {}

    public synchronized static MspStore getInstance() {
        if ( singleton==null ) {
            singleton = new MspStore();
            try {
                singleton.init();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return singleton;
    }

    /**
     * 得到ＭＳＰ對象
     * @return
     * @throws IOException
     */
    private Msp init() throws IOException {

        if ( msp==null ) {

            log.info(format("\nMSP_DIR is %s , \nCONFIG_DIR is %s", MSP_DIR, CONFIG_DIR));

            File caCertFile = new File(Paths.get(MSP_DIR, "cacerts").toString());
            for (File file : Objects.requireNonNull(caCertFile.listFiles())) {
                caCerts.add(FileUtils.readFileToByteArray(file));
            }

            File adminCertFile = new File(Paths.get(MSP_DIR, "admincerts").toString());
            for (File file : Objects.requireNonNull(adminCertFile.listFiles())) {
                adminCerts.add(FileUtils.readFileToByteArray(file));
            }

            File tlsCertFile = new File(Paths.get(MSP_DIR, "tlscacerts").toString());
            for (File file : Objects.requireNonNull(tlsCertFile.listFiles())) {
                tlsCaCerts.add(FileUtils.readFileToByteArray(file));
            }

            File configFile = new File(Paths.get(CONFIG_DIR, "config.yaml").toString());
            List<byte[]> configContent = new ArrayList<>();
            configContent.add(FileUtils.readFileToByteArray(configFile));
            configMap = new Yaml().load(new FileInputStream(configFile));

            File signCertFile = new File(Paths.get(MSP_DIR, "signcerts").toString());
            for (File file : Objects.requireNonNull(signCertFile.listFiles())) {
                signCerts.add(FileUtils.readFileToByteArray(file));
            }

            File clientCertsFile = new File(Paths.get(MSP_DIR, "clientcerts").toString());
            for (File file : Objects.requireNonNull(clientCertsFile.listFiles())) {
                clientCerts.add(FileUtils.readFileToByteArray(file));
            }

            File tlsClientCertsFile = new File(Paths.get(MSP_DIR, "tlsclientcerts").toString());
            for (File file : Objects.requireNonNull(tlsClientCertsFile.listFiles())) {
                tlsClientCerts.add(FileUtils.readFileToByteArray(file));
            }

            File privateKeyFolder = new File(Paths.get(MSP_DIR, "keystore").toString());
            log.info(format("\nprivateKeyFolder exists is %s", privateKeyFolder.exists()));
            for (File file : Objects.requireNonNull(privateKeyFolder.listFiles(new FilenameFilter() {
                @Override
                public boolean accept(File dir, String name) {
                    return name.endsWith("_sk");
                }
            }))) {
                this.serverKeys.add(FileUtils.readFileToByteArray(file));
            }

            File clientKeyFolder = new File(Paths.get(MSP_DIR, "clientkeys").toString());
            log.info(format("\nclientsKeyFolder exists is %s", clientKeyFolder.exists()));
            for (File file : Objects.requireNonNull(clientKeyFolder.listFiles())) {
                this.clientKeys.add(FileUtils.readFileToByteArray(file));
            }

            String mspId = GlobalMspManagement.getLocalMsp().getIdentifier();
            MspConfigPackage.MSPConfig mspConfig = MspConfigBuilder.mspConfigBuilder(mspId, caCerts, signCerts, adminCerts, clientCerts, new ArrayList<>(), configContent, tlsCaCerts, new ArrayList<>()).build();

            msp = new Msp(mspConfig);

        }
        return msp;
    }

    public ICsp getCsp() {
        return CspHelper.getCsp();
    }

//    /**
//     * 得到嘶鑰對象
//     * @return
//     * @throws JavaChainException
//     */
//    public IKey loadServerPrivateKey() throws JavaChainException {
//        return CspHelper.loadPrivateKey(Paths.get(MSP_DIR, "keystore").toString());
//    }

    /**
     * 序列化
     * @param mspId
     * @param cert
     * @return
     */
    public static byte[] serializeIdentity(String mspId, Certificate cert) {

        Identities.SerializedIdentity.Builder serializedIdentity = Identities.SerializedIdentity.newBuilder();
        serializedIdentity.setMspid(mspId);
        try {
            serializedIdentity.setIdBytes(ByteString.copyFrom(cert.getEncoded()));
            return serializedIdentity.build().toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 反序列化
     * @param serializedIdentity
     * @return
     */
    public static IIdentity deserializeIdentity(byte[] serializedIdentity) {
        ICsp csp = CspHelper.getCsp();
        Msp msp = null;
        try {
            msp = MspStore.getInstance().init();
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            Identities.SerializedIdentity sId = Identities.SerializedIdentity.parseFrom(serializedIdentity);
            Certificate cert = Certificate.getInstance(sId.getIdBytes().toByteArray());
            byte[] pbBytes = cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
            IKey certPubK = csp.keyImport(pbBytes, new SM2PublicKeyImportOpts(true));
            String identifier_Id;
            byte[] resultBytes = csp.hash(cert.toString().getBytes(), null);
            //转换成十六进制字符串表示
            identifier_Id = Hex.toHexString(resultBytes);
            IdentityIdentifier identityIdentifier = new IdentityIdentifier(sId.getMspid(), identifier_Id);
            IIdentity identity = new Identity(identityIdentifier, cert, certPubK, msp);
            return identity;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        Msp msp = null;
        try {
            msp = MspStore.getInstance().init();
            log.info(msp.toString());
            IKey privateKey = CertificateUtils.bytesToPrivateKey(MspStore.getInstance().getClientKeys().get(0));
            log.info(privateKey.toString());

            log.info(MspStore.getInstance().getAdminCerts().toString());
            log.info(MspStore.getInstance().getCaCerts().toString());
            log.info(MspStore.getInstance().getTlsCaCerts().toString());
            log.info(MspStore.getInstance().getTlsClientCerts().toString());
            log.info(MspStore.getInstance().getClientCerts().toString());
            log.info(MspStore.getInstance().getSignCerts().toString());
            log.info(MspStore.getInstance().getConfigMap().toString());


            log.info(CertificateUtils.bytesToX509Certificate(MspStore.getInstance().getAdminCerts().get(0)).toString());
            log.info(CertificateUtils.bytesToX509Certificate(MspStore.getInstance().getCaCerts().get(0)).toString());
            log.info(CertificateUtils.bytesToX509Certificate(MspStore.getInstance().getTlsCaCerts().get(0)).toString());
            log.info(CertificateUtils.bytesToX509Certificate(MspStore.getInstance().getSignCerts().get(0)).toString());


            byte[] result = serializeIdentity("Org1Msp", CertificateUtils.bytesToX509Certificate(MspStore.getInstance().getClientCerts().get(0)));
            log.info(new String(result));
            IIdentity identity = deserializeIdentity(result);
            log.info(identity.toString());

        } catch (IOException e) {
            e.printStackTrace();
        } catch (JavaChainException e) {
            e.printStackTrace();
        }

//        Identities.SerializedIdentity.newBuilder()
//                .setIdBytes(ByteString.copyFromUtf8(MspStore.getInstance().get))
//                .setMspid("").build();



        //實驗一下籤名
        ILocalSigner signer = new LocalSigner();
        byte[] msg = "我今天在球場沒拖地".getBytes();
        byte[] sig = signer.sign("我今天在球場沒拖地".getBytes());
        boolean verify = false;
        Certificate cert = null;
        IKey certPubK = null;
        try {
            cert = CertificateUtils.bytesToX509Certificate(MspStore.getInstance().getSignCerts().get(0));
            byte[] pbBytes = cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
            certPubK = MspStore.getInstance().getCsp().keyImport(pbBytes, new SM2PublicKeyImportOpts(true));
        } catch (JavaChainException e) {
            e.printStackTrace();
        }


        try {
            verify = MspStore.getInstance().getCsp().verify(certPubK, sig, msg, new SM2SignerOpts());

            if (verify == false) {
                throw new VerifyException("Veify the sign is fail");
            }
        } catch (JavaChainException e) {
            e.printStackTrace();
        }
    }
}