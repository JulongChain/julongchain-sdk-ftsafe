/**
 * Copyright DingXuan. All Rights Reserved.
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
package org.bcia.javachain.sdk.security.csp.gm.dxct.sm2;

import org.bcia.javachain.sdk.security.csp.intfs.opts.IKeyGenOpts;

/**
 * sm2 蜜钥生成选项
 * @author zhangmingyang
 * @Date: 2018/3/27
 * @company Dingxuan
 */
public class SM2KeyGenOpts implements IKeyGenOpts {
    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public boolean isEphemeral() {
        return false;
    }
}
