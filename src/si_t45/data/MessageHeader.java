package si_t45.data;

import java.util.ArrayList;
import si_t45.util.Util;

public class MessageHeader
{
    public int id = 0;
    public boolean qr = false;
    public int opcode = 0;
    public boolean aa = false;
    public boolean tc = false; // I don't use it.
    public boolean rd = false;
    public boolean ra = false;
    public boolean z = false; // This isn't used.
    public boolean ad = false;
    public boolean cd = false;
    public int rcode = 0;
    public int qdcount = 0;
    public int ancount = 0;
    public int nscount = 0;
    public int arcount = 0;

    public MessageHeader()
    {
    }

    public byte[] toBytes()
    {
        byte[] p1 = Util.shortToBytes(id);
        byte[] p2 = new byte[2];
        byte[] p3 = Util.shortToBytes(qdcount);
        byte[] p4 = Util.shortToBytes(ancount);
        byte[] p5 = Util.shortToBytes(nscount);
        byte[] p6 = Util.shortToBytes(arcount);

        if (qr)
            p2[0] |= 1;
        p2[0] |= (opcode & 0xf) << 1;
        if (aa)
            p2[0] |= 1 << 5;
        if (tc)
            p2[0] |= 1 << 6;
        if (rd)
            p2[0] |= 1 << 7;
        if (ra)
            p2[1] |= 1;
        if (z)
            p2[1] |= 1 << 1;
        if (ad)
            p2[1] |= 1 << 2;
        if (cd)
            p2[1] |= 1 << 3;
        p2[1] |= (rcode & 0xf) << 4;

        return Util.catBytes(p1, p2, p3, p4, p5, p6);
    }

    public static MessageHeader fromBytes(ArrayList<Byte> b)
    {
        MessageHeader ret = new MessageHeader();

        ret.id = Util.getShortFromByteArrayList(b);
        byte[] p2 = new byte[2];
        p2[0] = b.remove(0);
        p2[1] = b.remove(0);
        ret.qdcount = Util.getShortFromByteArrayList(b);
        ret.ancount = Util.getShortFromByteArrayList(b);
        ret.nscount = Util.getShortFromByteArrayList(b);
        ret.arcount = Util.getShortFromByteArrayList(b);

        if ((p2[0] & 1) > 0)
            ret.qr = true;
        ret.opcode = (p2[0] >> 1) & 0xf;
        if ((p2[0] & (1<<5)) > 0)
            ret.aa = true;
        if ((p2[0] & (1<<6)) > 0)
            ret.tc = true;
        if ((p2[0] & (1<<7)) > 0)
            ret.rd = true;
        if ((p2[1] & 1) > 0)
            ret.ra = true;
        if ((p2[1] & (1<<1)) > 0)
            ret.z = true;
        if ((p2[1] & (1<<2)) > 0)
            ret.ad = true;
        if ((p2[1] & (1<<3)) > 0)
            ret.cd = true;
        ret.rcode = (p2[1] >> 4) & 0xf;

        return ret;
    }

    @Override
    public String toString()
    {
        String ret = "";

        if (qr)
            ret += "Response";
        else
            ret += "Query";

        if (aa)
            ret += " AA";

        if (ra)
            ret += " RA";

        if (rd)
            ret += " RD";

        if (ad)
            ret += " AD";

        if (cd)
            ret += " CD";

        ret += " ID=" + id;
        ret += " OPCODE=" + opcode;
        ret += " RCODE=" + rcode;

        return ret;
    }
}
