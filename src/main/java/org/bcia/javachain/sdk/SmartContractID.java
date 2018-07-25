/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

/**
 * SmartContractID identifies smartContract.
 * 
 * modified for Node,SmartContractPackage,Consenter,
 * Group,TransactionPackage,TransactionResponsePackage,
 * EventsPackage,ProposalPackage,ProposalResponsePackage
 * by wangzhe in ftsafe 2018-07-02
 */
public final class SmartContractID {

    private final org.bcia.julongchain.protos.node.SmartContractPackage.SmartContractID smartcontractID;

    public org.bcia.julongchain.protos.node.SmartContractPackage.SmartContractID getSmartContractID() {
        return smartcontractID;
    }

    SmartContractID(org.bcia.julongchain.protos.node.SmartContractPackage.SmartContractID chaincodeID) {
        this.smartcontractID = chaincodeID;
    }

    public String getName() {
        return smartcontractID.getName();
    }

    public String getPath() {
        return smartcontractID.getPath();

    }

    public String getVersion() {
        return smartcontractID.getVersion();

    }

    @Override
    public String toString() {
        return "SmartContractID(" + getName() + ":" + getPath() + ":" + getVersion() + ")";
    }

    /**
     * Build a new SmartContractID
     */

    public static final class Builder {
        private final org.bcia.julongchain.protos.node.SmartContractPackage.SmartContractID.Builder protoBuilder = org.bcia.julongchain.protos.node.SmartContractPackage.SmartContractID.newBuilder();

        private Builder() {
        }

        /**
         * @param name of the SmartContractPackage
         * @return Builder
         */

        public Builder setName(String name) {
            this.protoBuilder.setName(name);
            return this;
        }

        /**
         * Set the version of the SmartContractPackage
         *
         * @param version of the chaincode
         * @return Builder
         */
        public Builder setVersion(String version) {
            this.protoBuilder.setVersion(version);
            return this;
        }

        /**
         * Set path of chaincode
         *
         * @param path of chaincode
         * @return Builder
         */

        public Builder setPath(String path) {
            this.protoBuilder.setPath(path);
            return this;
        }

        public SmartContractID build() {
            return new SmartContractID(this.protoBuilder.build());
        }
    }

    /**
     * SmartContractPackage builder
     *
     * @return SmartContractID builder.
     */

    public static Builder newBuilder() {
        return new Builder();
    }

}
