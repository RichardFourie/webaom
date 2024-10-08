/*
 * Created on 23.mai.2006 18:55:12
 * Filename: FileInfo.java
 */
package epox.av;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

import epox.util.U;
import epox.webaom.data.AMap;

public class FileInfo {

    public ArrayList<AMap> vid, aud, sub;
    public String m_xml = null;

    public FileInfo(String xml) throws IOException {
        vid = new ArrayList<>();
        aud = new ArrayList<>();
        sub = new ArrayList<>();
        byXml(xml);
    }

    private static void dump(ArrayList<AMap> v) {

        for (AMap element : v) {
            String[][] a = element.toArray();

            for (String[] element2 : a) {
                System.out.println(element2[0] + ": " + element2[1]);
            }
        }
    }

    public void dump() {
        FileInfo.dump(vid);
        FileInfo.dump(aud);
        FileInfo.dump(sub);
    }

    protected class MyHandler extends DefaultHandler {
        final static int DUR = 0, VID = 1, AUD = 2, SUB = 3;
        int ctyp = -1, tcnt = 1;
        String name = null, id = null;
        AMap m;

        /*
         * private void o(Object o){ System.out.println(o); }
         */
        @Override
        public void startElement(String namespace, String localname, String type, org.xml.sax.Attributes attributes)
                throws org.xml.sax.SAXException {
            name = type;
            id = attributes.getValue("id");

            // o("> "+type);
            if (ctyp > 0) {
                return;
            }

            // if(type.equals("duration")) ctyp = DUR;
            if ("vid".equals(type)) {
                ctyp = MyHandler.VID;
            } else if ("aud".equals(type)) {
                ctyp = MyHandler.AUD;
            } else if ("sub".equals(type)) {
                ctyp = MyHandler.SUB;
            } else {
                ctyp = -1;
            }

            if (ctyp > 0) {
                m = new AMap();
                String d = attributes.getValue("default");
                m.put("def", d != null && "1".equals(d) ? "default" : "");
                m.put("num", tcnt++);
            }
        }

        @Override
        public void endElement(String namespace, String localname, String type) throws org.xml.sax.SAXException {
            // o("< "+type);

            if ("vid".equals(type) && ctyp == MyHandler.VID) {
                vid.add(m);
                m = null;
                ctyp = -1;
                return;
            }

            if ("aud".equals(type) && ctyp == MyHandler.AUD) {
                aud.add(m);
                m = null;
                ctyp = -1;
                return;
            }

            if ("sub".equals(type) && ctyp == MyHandler.SUB) {
                sub.add(m);
                m = null;
                ctyp = -1;
            }
        }

        @Override
        public void characters(char[] ch, int start, int len) {
            String text = new String(ch, start, len).trim();

            if (text.length() < 1) {
                return;
            }

            if (m != null) {
                // o("put("+name+", "+text+") "+(id==null?"":id));
                m.put(name, text);
            }
        }
    }

    public void byXml(String str) throws IOException {

        try {
            MyHandler myh = new MyHandler();
            XMLReader xml = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
            xml.setContentHandler(myh);
            xml.parse(new InputSource(new StringReader(str)));
            m_xml = str.replaceAll("[\r\n\t]", "").replace("  ", " ");
        } catch (SAXException | ParserConfigurationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } /*
           * catch (IOException e) { // TODO Auto-generated catch block
           * e.printStackTrace(); }
           */
    }

    /*
     * public void add(GenericTrack gt){ AMap m = new AMap(); m.put("%tnum",
     * gt.num); m.put("%tdef", (gt.def?"default":"")); m.put("%name", gt.name);
     * m.put("%size", U.sbyte((long)gt.size)); if(gt instanceof VideoTrack || gt
     * instanceof AudioTrack) { m.put("%cdci", gt.codec_id); m.put("%bitr",
     * (int)(gt.size*8/gt.dur/1000)); m.put("%dura", ""+gt.dur); if(gt instanceof
     * VideoTrack){ VideoTrack vt = (VideoTrack) gt; m.put("%cdcs",
     * str_vcdc(gt.codec_id)); m.put("%pres", vt.pixel_width+"x"+vt.pixel_height);
     * m.put("%dres", vt.display_width+"x"+vt.display_height); m.put("%vfps",
     * vt.vfr?"vfr":""+(vt.fps/1000f)); m.put("%flag", str_vflag(0));
     *
     * vid.add(m.toArray()); }else{ AudioTrack at = (AudioTrack) gt; m.put("%cdcs",
     * str_acdc(gt.codec_id)); m.put("%chan", str_chn(at.channels)); m.put("%samp",
     * at.samplerate); m.put("%lang", gt.lang); aud.add(m.toArray()); } }else{
     * m.put("%lang", gt.lang); m.put("%type", gt.codec); m.put("%flag",
     * str_vflag(0)); sub.add(m.toArray()); }
     *
     * }
     */
    public String convert(String schema, int type) {

        if (schema == null) {
            return null;
        }
        ArrayList<AMap> v = null;

        switch (type) {
        case 0:
            v = vid;
            break;
        case 1:
            v = aud;
            break;
        case 2:
            v = sub;
            break;
        default:
            return null;
        }
        StringBuilder sb = new StringBuilder(schema.length() * v.size());

        for (int j = 0; j < v.size(); j++) {
            String s = U.replaceCCCode(schema, v.get(j));

            if (j > 0) {
                sb.append('\n');
            }
            sb.append(s);
        }
        return sb.toString();
    }
    /*
     * private static String str_chn(int i){ switch(i){ case 1: return "Mono"; case
     * 2: return "Stereo"; case 4: return "Dolby Surround"; case 5: case 6: return
     * "5.1 Surround"; case 7: return "6.1 Surround"; case 8: return "7.1 Surround";
     * default: return "Unknown"; } } private static String str_vcdc(int i){
     * switch(i){ case 1: return "Unknown"; case 2: return "DivX Unknown"; case 3:
     * return "DivX3"; case 5: return "DivX4"; case 7: return "DivX5/6"; case 9:
     * return "MPEG-1"; case 10: return "MPEG-2"; case 11: return "ASP Other"; case
     * 12: return "Other(non-ASP)"; case 14: return "RV Other"; case 17: return
     * "XviD"; case 18: return "MS MP4x"; case 19: return "WMV9/3"; case 20: return
     * "RV9/10(rv40)"; case 22: return "H264/AVC"; default: return "Invalid"; } }
     * private static String str_acdc(int i){ switch(i){ case 1: return "Unknown";
     * case 2: return "AC3"; case 3: return "WMA (DivX Audio)"; case 5: return
     * "MP3 CBR"; case 6: return "MP3 VBR"; case 7: return "MS Audio"; case 8:
     * return "Ogg Vorbis"; case 9: return "AAC"; case 10: return "PCM"; case 11:
     * return "MP2"; case 13: return "DTS"; case 15: return "Other"; default: return
     * "Invalid"; } } private static String str_vflag(int i){ if(i<1) return "";
     * StringBuffer sb = new StringBuffer(); return sb.toString(); }
     */
}
