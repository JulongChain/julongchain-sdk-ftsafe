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
        String identityHex = "0a0744454641554c5412c703308201c330820167a0030201020204289d6a85300c06082a811ccf5501837505003072311c301a0603550403131363612e6f7267312e6578616d706c652e636f6d31193017060355040a13106f7267312e6578616d706c652e636f6d3109300706035504061300310b3009060355040b13024a4c310930070603550407130031093007060355040813003109300706035504091300301e170d3138303832343031333434305a170d3238303832343031333434305a3049310930070603550409130031093007060355040813003109300706035504071300310b3009060355040b13024a4c3109300706035504061300310e300c060355040313056e6f6465303059301306072a8648ce3d020106082a811ccf5501822d034200047ff0b301e693ba965b4f9188ff95391a18c576d638efe5bea6e6a6d376fc30a699a32214ea641bb447bc2e6b1809483ebee835bca0be9db016eb68a1d3a110baa3123010300e0603551d0f0101ff040403020780300c06082a811ccf550183750500034800304502202aa9a69c060f1c888670a3d56db6136ff70c00212354f47d631e1310a77d7b700221009816aee96edb4f3d930f4948de8f0069070cc131ed92fb12cecaa66f49ffcfe7";
        byte[] identityBytes = Hex.decode(identityHex);
        IIdentity identity = MspStore.deserializeIdentity(identityBytes);
        identity.validate();
        byte[] sigbyte = Hex.decode("30450220616fbd20272c783061cad70c247ee6ff04d4db5a9aeb3bf068476ad5003a1b910221008e7e61f4355544f2daea8a532db8ef7b4aaf1e65acb29a8b16c2451a5f3a97de");
        identity.verify("继续走永远流留着我的笑容".getBytes(), sigbyte);

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
