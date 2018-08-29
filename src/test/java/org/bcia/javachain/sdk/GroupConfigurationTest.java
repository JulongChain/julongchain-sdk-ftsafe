/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.io.FileInputStream;
import java.io.IOException;

import org.bcia.julongchain.protos.common.Common.Envelope;
import org.junit.Assert;
import org.junit.Test;

import com.google.protobuf.InvalidProtocolBufferException;

public class GroupConfigurationTest {
    private static final String TEST_BYTES_1 = "0A205E87B04D3B137E4F";
    private static final String TEST_BYTES_2 = "00112233445566778899";

    @Test
    public void testGroupConfigurationByeArray() {
        // Test empty constructor
        new GroupConfiguration();

        // Test byte array constructor
        GroupConfiguration testChannelConfig = new GroupConfiguration(TEST_BYTES_1.getBytes());
        testChannelConfig.setGroupConfiguration(TEST_BYTES_2.getBytes());
        Assert.assertEquals(TEST_BYTES_2, new String(testChannelConfig.getGroupConfigurationAsBytes()));
    }
    
    @Test
    public void testLoad() {
    	FileInputStream fis = null;
    	try {
			fis = new FileInputStream("/home/bcia/javachain-sdk-ftsafe/src/test/fixture/sdkintegration/e2e-2Orgs/v1.1/bar.tx");
			int len = fis.available();
			byte[] bytes = new byte[len];
			fis.read(bytes);
			Envelope ccEnvelope = Envelope.parseFrom(bytes);
			
			System.out.println(ccEnvelope);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
    	byte[] bytes = null;
    	try {
			Envelope ccEnvelope = Envelope.parseFrom(bytes);
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
		}
    }
}
