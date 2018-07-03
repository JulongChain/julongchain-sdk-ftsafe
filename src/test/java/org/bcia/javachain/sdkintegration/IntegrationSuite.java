/*
 Copyright IBM Corp. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/
package org.bcia.javachain.sdkintegration;

import org.bcia.javachain_ca.sdkintegration.HFCAClientIT;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith (Suite.class)

@Suite.SuiteClasses (
        {
                End2endIT.class,
                End2endAndBackAgainIT.class,
                UpdateGroupIT.class,
                NetworkConfigIT.class,
                End2endNodeIT.class,
                End2endAndBackAgainNodeIT.class,
                HFCAClientIT.class
        })
public class IntegrationSuite {

}
