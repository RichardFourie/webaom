/*
 * Created on 23.mai.2006 12:20:33
 * Filename: AVdump.java
 */
package epox.av;

import java.io.File;
import java.io.IOException;

public class AVInfo {
    private static final int BUFFER_SIZE = 4096, FILE_MKV = 0, FILE_OGM = 1,
//		FILE_MP4=2, //use VAR
            FILE_VAR = 3, // mediainfo

//		TRACK_AUDIO=2,
//		TRACK_VIDEO=1,
//		TRACK_SUBTITLE=17,

//		UNKNOWN=-1,

            FORMAT_OLD = 0, FORMAT_XML = 1, FORMAT_SHORT = 2;

    private static native int version();

    private native long fileOpen(String path, int type);

    private native float fileParse(long addr);

    private native float fileDuration(long addr);

    private native int fileTrackCount(long addr);

    private native void fileClose(long addr);

    private native String fileFormatted(long addr, int type, int blen);

    private native boolean trackGetGeneric(long addr, int nr, GenericTrack gt);

    private native boolean trackGetVideo(long addr, int nr, VideoTrack vt);

    private native boolean trackGetAudio(long addr, int nr, AudioTrack at);

    private static boolean inited = false;
    static {
        try {
            System.loadLibrary("avinfo");

            if (AVInfo.version() == 1) {
                AVInfo.inited = true;
            }
        } catch (@SuppressWarnings("unused") java.lang.UnsatisfiedLinkError e) {
            // e.printStackTrace();
        }
    }

    public static boolean ok() {
        return AVInfo.inited;
    }

    private static final String EC = "Error: instance is closed.";

    private File file;
    private long address;

    // private Vector tracks;
    public AVInfo(File f) throws IOException {
        if (!AVInfo.inited) {
            throw new IOException("Error: dll not found.");
        }

        if (!f.exists()) {
            throw new IOException("Error: file not found.");
        }
        this.file = f;
        int type = AVInfo.FILE_VAR;

        if (file.getName().endsWith(".mkv")) {
            type = AVInfo.FILE_MKV;
        }

        if (file.getName().endsWith(".ogm")) {
            type = AVInfo.FILE_OGM;
        }
        address = fileOpen(file.getAbsolutePath(), type);

        if (address < 1) {
            throw new IOException("Error: dll returned null.");
            // tracks = new Vector();
        }
    }

    public void close() throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }
        fileClose(address);
        address = 0;
    }

    public float parse() throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }

        return fileParse(address);
    }

    public int trackCount() throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }

        return fileTrackCount(address);
    }

    public float duration() throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }

        return fileDuration(address);
    }

    public GenericTrack getGeneric(int n) throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }
        GenericTrack gt = new GenericTrack();
        gt.num = n;

        if (trackGetGeneric(address, n, gt)) {
            return gt;
        }

        return null;
    }

    public VideoTrack getVideo(GenericTrack gt) throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }
        VideoTrack vt = new VideoTrack(gt);

        if (trackGetVideo(address, gt.num, vt)) {
            return vt;
        }

        return null;
    }

    public AudioTrack getAudio(GenericTrack gt) throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }
        AudioTrack at = new AudioTrack(gt);

        if (trackGetAudio(address, gt.num, at)) {
            return at;
        }

        return null;
    }

    public FileInfo build() throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }

        /*
         * for(int i=0; i<trackCount(); i++){ GenericTrack gt = getGeneric(i);
         *
         * switch(gt.type_id){ case TRACK_VIDEO: fi.add(getVideo(gt)); break; case
         * TRACK_AUDIO: fi.add(getAudio(gt)); break; case TRACK_SUBTITLE: fi.add(gt);
         * break; } }
         */
        return new FileInfo(toXML());
    }

    public String toOld() throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }

        return fileFormatted(address, AVInfo.FORMAT_OLD, AVInfo.BUFFER_SIZE);
    }

    public String toXML() throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }

        return fileFormatted(address, AVInfo.FORMAT_XML, AVInfo.BUFFER_SIZE);
    }

    public String toShort() throws IOException {
        if (address < 1) {
            throw new IOException(AVInfo.EC);
        }

        return fileFormatted(address, AVInfo.FORMAT_SHORT, AVInfo.BUFFER_SIZE);
    }
}
