package cn.myflv.kernel;

public interface ReKernelXCallback {

    /** binderType: a binder transaction call */
    int BINDER_TRANSACTION      = 1;
    /** binderType: a binder transaction reply */
    int BINDER_REPLY            = 2;
    /** binderType: free-buffer exhaustion burst */
    int BINDER_FREE_BUFFER_FULL = 3;

    /** proto: IPv4 */
    int PROTO_IPV4 = 4;
    /** proto: IPv6 */
    int PROTO_IPV6 = 6;

    /**
     * @param binderType {@link #BINDER_TRANSACTION}, {@link #BINDER_REPLY},
     *                   or {@link #BINDER_FREE_BUFFER_FULL}
     * @param oneway     1 if async, 0 if sync
     * @param fromUid    uid of the sender
     * @param fromPid    pid of the sender
     * @param targetUid  uid of the target (frozen process)
     * @param targetPid  pid of the target (frozen process)
     * @param rpcName    interface token name
     * @param code       transaction code
     */
    void binder(int binderType, int oneway, int fromUid, int fromPid, int targetUid, int targetPid, String rpcName, int code);

    /**
     * @param signal     signal number sent
     * @param killerUid  uid of the process sending the signal
     * @param killerPid  pid of the process sending the signal
     * @param dstUid     uid of the target process
     * @param dstPid     pid of the target process
     */
    void signal(int signal, int killerUid, int killerPid, int dstUid, int dstPid);

    /**
     * @param proto     {@link #PROTO_IPV4} or {@link #PROTO_IPV6}
     * @param targetUid uid being monitored
     * @param dataLen   length of the observed payload
     */
    void network(int proto, int targetUid, int dataLen);

}
