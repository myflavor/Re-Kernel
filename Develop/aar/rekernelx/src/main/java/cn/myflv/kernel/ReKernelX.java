package cn.myflv.kernel;

public class ReKernelX {

    static {
        System.loadLibrary("ReKernelX");
    }

    public static native boolean startListening(ReKernelXCallback callback);

    public static native void stopListening();


    public static native boolean addMonitorNet(int uid);
    public static native boolean delMonitorNet(int uid);


}
