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

package org.bcia.javachain.sdk.transaction;

import com.google.protobuf.ByteString;
import org.bcia.javachain.sdk.Group;
import org.bcia.javachain.sdk.HFClient;
import org.bcia.javachain.sdk.TestHFClient;
import org.bcia.javachain.sdk.User;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.lang.reflect.Constructor;

public class TransactionContextTest {

    public final TemporaryFolder tempFolder = new TemporaryFolder();
    static HFClient hfclient = null;

    @BeforeClass
    public static void setupClient() {

        try {
            hfclient = TestHFClient.newInstance();

        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());

        }
    }

    /**
     * 测试签名
     * @throws Exception
     */
    @Test
    public void testSignByteStrings() throws Exception {

        TransactionContext context = createTestContext();

        Assert.assertNull(context.signByteStrings((ByteString) null));
        Assert.assertNull(context.signByteStrings((ByteString[]) null));
        Assert.assertNull(context.signByteStrings(new ByteString[0]));

        User[] users = new User[0];
        Assert.assertNull(context.signByteStrings(users, (ByteString) null));
        Assert.assertNull(context.signByteStrings(users, (ByteString[]) null));
        Assert.assertNull(context.signByteStrings(users, new ByteString[0]));

    }

    // ==========================================================================================
    // Helper methods
    // ==========================================================================================

    /**
     * 创建测试交易上下文
     * @return
     */
    private TransactionContext createTestContext() {
        Group channel = createTestGroup("channel1");
        User user = hfclient.getUserContext();
        return new TransactionContext(channel, user);
    }

    /**
     * 测试群组创建
     * @param channelName
     * @return
     */
    private Group createTestGroup(String channelName) {

        Group channel = null;

        try {
            Constructor<?> constructor = Group.class.getDeclaredConstructor(String.class, HFClient.class);
            constructor.setAccessible(true);

            channel = (Group) constructor.newInstance(channelName, hfclient);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }

        return channel;
    }

}
