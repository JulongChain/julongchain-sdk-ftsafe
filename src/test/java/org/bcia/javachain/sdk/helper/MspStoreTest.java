package org.bcia.javachain.sdk.helper;

import org.apache.commons.io.IOUtils;
import org.bcia.javachain.common.exception.JavaChainException;
import org.bcia.javachain.common.localmsp.ILocalSigner;
import org.bcia.javachain.common.localmsp.impl.LocalSigner;
import org.bcia.javachain.common.util.FileUtils;
import org.bcia.javachain.sdk.security.gm.CertificateUtils;
import org.bcia.javachain.sdk.security.msp.IIdentity;
import org.bouncycastle.asn1.x509.Certificate;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.IOException;
import java.nio.file.Paths;
import static java.lang.String.format;
import org.bouncycastle.util.encoders.Hex;

public class MspStoreTest {

    private Logger log = LoggerFactory.getLogger(MspStoreTest.class);

    @Test
    public void testSerializeIdentity() throws JavaChainException, IOException {
        String path = Paths.get(System.getProperty("user.dir"), "msp", "signcerts", "node0-cert.pem").toString();
        log.info(format("path: %s", path));
        byte[] certBytes = FileUtils.readFileBytes(path);
        Certificate cert = CertificateUtils.bytesToX509Certificate(certBytes);
        byte[] identityBytes = MspStore.serializeIdentity("DEFAULT", cert);
        String identityHex = Hex.toHexString(identityBytes);
        log.info(format("<<\n%s\n>>", identityHex));
        ILocalSigner signer = new LocalSigner();
        String msg = "继续走永远流留着我的笑容";
        byte[] sigBytes = signer.sign(msg.getBytes());
        log.info(format("sig:%s", Hex.toHexString(sigBytes)));
    }


    @Test
    public void testDeserializeIdentity() throws JavaChainException, IOException {
        String path = Paths.get(System.getProperty("user.dir"), "msp", "signcerts", "node0-cert.pem").toString();
        log.info(format("path: %s", path));
        byte[] certBytes = FileUtils.readFileBytes(path);
        Certificate cert = CertificateUtils.bytesToX509Certificate(certBytes);
        String identityHex = Hex.toHexString(MspStore.serializeIdentity("DEFAULT", cert));
        ILocalSigner signer = new LocalSigner();
        String msg = "继续走永远流留着我的笑容";
        byte[] sigBytes = signer.sign(msg.getBytes());
        byte[] identityBytes = Hex.decode(identityHex);
        IIdentity identity = MspStore.deserializeIdentity(identityBytes);
        identity.validate();
        identity.verify("继续走永远流留着我的笑容".getBytes(), sigBytes);

    }

    @Test
    public void testHex() throws IOException {
        String path = Paths.get(System.getProperty("user.dir"), "msp", "signcerts", "node0-cert.pem").toString();
        log.info(format("path: %s", path));
        byte[] certBytes = FileUtils.readFileBytes(path);
        log.info(new String(certBytes));
        String certHex = Hex.toHexString(certBytes);
        byte[] certBytes2 = Hex.decode(certHex);
        log.info(new String(certBytes2));
        Assert.assertEquals(certBytes.length, certBytes2.length);
    }

}
