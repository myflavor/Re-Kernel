package cn.myflv.kernel;

public interface ReKernelXCallback {

    /** binderType: a binder transaction call */
    int BINDER_TRANSACTION      = 0;
    /** binderType: a binder transaction reply */
    int BINDER_REPLY            = 1;
    /** binderType: free-buffer exhaustion burst */
    int BINDER_FREE_BUFFER_FULL = 2;

    /** proto: IPv4 */
    int PROTO_IPV4 = 4;
    /** proto: IPv6 */
    int PROTO_IPV6 = 6;

    /**
     * Called only when the netlink connection drops unexpectedly
     * (recv error while still running). Not invoked on a clean
     * {@link ReKernelX#stopListening()}.
     */
    void disconnected();

    /**
     * @param binderType {@link #BINDER_TRANSACTION}, {@link #BINDER_REPLY},
     *                   or {@link #BINDER_FREE_BUFFER_FULL}
     */
    void binder(int binderType, int oneway, int from, int fromPid, int target, int targetPid, String rpcName, int code);

    /**
     * @param signal   signal number sent
     * @param killer   uid of the process sending the signal
     * @param killerPid pid of the process sending the signal
     * @param dst      uid of the target process
     * @param dstPid   pid of the target process
     */
    void signal(int signal, int killer, int killerPid, int dst, int dstPid);

    /**
     * @param proto   {@link #PROTO_IPV4} or {@link #PROTO_IPV6}
     * @param target  uid being monitored
     * @param dataLen length of the observed payload
     */
    void network(int proto, int target, int dataLen);

}
