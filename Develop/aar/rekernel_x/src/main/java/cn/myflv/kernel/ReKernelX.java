package cn.myflv.kernel;

public class ReKernelX {

    static {
        System.loadLibrary("ReKernelX");
    }

    /**
     * Install (or replace) the business-event callback. May be called with
     * {@code null} to clear a previously installed callback. Must be set
     * before {@link #pollEvent()} will dispatch anything.
     *
     * The callback runs on whatever thread is blocked in {@link #pollEvent()};
     * its implementation MUST NOT call {@link #connect()}, {@link #disconnect()}
     * or {@link #pollEvent()} — doing so would self-deadlock.
     */
    public static native void setCallback(ReKernelXCallback callback);

    /**
     * Non-blocking: build the netlink socket, resolve the genl family and join
     * the multicast group. Returns {@code true} on success.
     *
     * @return {@code true} if connected and ready to {@link #pollEvent()}
     */
    public static native boolean connect();

    /**
     * Call from a thread OTHER than the one blocked in {@link #pollEvent()}
     * (typically the thread that called {@link #connect()}). Closes the
     * socket, which wakes {@link #pollEvent()} and makes it return.
     */
    public static native void disconnect();

    /**
     * BLOCKS the calling thread. Receives kernel events and dispatches them to
     * the installed {@link ReKernelXCallback} until the connection drops —
     * either because {@link #disconnect()} was called from another thread, or
     * because of a recv error. Returning means "disconnected"; the caller owns
     * any reconnect logic.
     */
    public static native void pollEvent();

    public static native boolean addMonitorNet(int uid);

    public static native boolean delMonitorNet(int uid);

}
