package org.bcia.javachain.sdkintegration;

import org.bcia.javachain.sdk.Group;
import org.bcia.javachain.sdk.HFClient;
import org.bcia.javachain.sdk.TransactionRequest.Type;
import org.bcia.javachain.sdk.exception.InvalidArgumentException;
import org.bcia.javachain.sdk.exception.ProposalException;
import org.junit.Test;

import java.io.IOException;


/*
    This runs a version of end2end but with Node chaincode.
    It requires that End2endIT has been run already to do all enrollment and setting up of orgs,
    creation of the channels. None of that is specific to chaincode deployment language.
 */

public class End2endNodeIT extends End2endIT {

    {

        testName = "End2endNodeIT";  //Just print out what test is really running.

        // This is what changes are needed to deploy and run Node code.

        // this is relative to src/test/fixture and is where the Node chaincode source is.
        CHAIN_CODE_FILEPATH = "sdkintegration/nodecc/sample1"; //override path to Node code
        CHAIN_CODE_PATH = null; //This is used only for GO.
        CHAIN_CODE_NAME = "example_cc_node"; // chaincode name.
        CHAIN_CODE_LANG = Type.NODE; //language is Node.
    }

    @Override
    void blockWalker(HFClient client, Group channel) throws InvalidArgumentException, ProposalException, IOException {
        // block walker depends on the state of the chain after go's end2end. Nothing here is language specific so
        // there is no loss in coverage for not doing this.
    }

    @Override
    @Test
    public void setup() throws Exception {
        sampleStore = new SampleStore(sampleStoreFile);
        enrollUsersSetup(sampleStore);
        runFabricTest(sampleStore); // just run fabric tests.
    }

    @Override
    Group constructGroup(String name, HFClient client, SampleOrg sampleOrg) throws Exception {
        // override this method since we don't want to construct the channel that's been done.
        // Just get it out of the samplestore!

        client.setUserContext(sampleOrg.getNodeAdmin());

        return sampleStore.getGroup(client, name).initialize();

    }
}
