package org.bcia.javachain.common.ledger.blockledger;

public class BlockConstant {

    private static final String BLOCKFILE_PREFIX = "blockfile";
    private static final byte[] BLK_MGR_INFO_KEY = "blkMgrInfo".getBytes();
    private static final byte BLOCK_BYTES_START = 10;

    public static final int LAST_BLOCK_BYTES = 0;
    public static final int CURRENT_OFFSET = 1;
    public static final int NUM_BLOCKS = 2;
    public static final Object lock = new Object();
    public static final int PEEK_BYTES_LEN = 8;
}
