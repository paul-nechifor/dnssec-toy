package net.nechifor.dnssec_toy.data;

import java.util.ArrayList;
import javax.xml.bind.DatatypeConverter;
import net.nechifor.dnssec_toy.util.Util;

public class RDataDs extends RData
{
    public int keyTag;
    public short algorithm;
    public short digestType;
    public String digest;

    public RDataDs()
    {
    }

    public RDataDs(String s)
    {
        String[] split = s.split(" ");
        keyTag = Integer.parseInt(split[0]);
        algorithm = Short.parseShort(split[1]);
        digestType = Short.parseShort(split[2]);
        digest = split[3];
    }

    public static RDataDs fromBytes(ArrayList<Byte> b)
    {
        RDataDs ret = new RDataDs();

        ret.keyTag = Util.getShortFromByteArrayList(b);
        ret.algorithm = Util.getByteFromByteArrayList(b);
        ret.digestType = Util.getByteFromByteArrayList(b);
        ret.digest = DatatypeConverter.printHexBinary(Util.byteArray(b));

        return ret;
    }

    @Override
    public String toString()
    {
        return keyTag + " " + algorithm + " " + digestType + " " + digest;
    }

    @Override
    public byte[] toBytes()
    {
        return Util.catBytes(
                Util.shortToBytes(keyTag),
                Util.byteToBytes(algorithm),
                Util.byteToBytes(digestType),
                DatatypeConverter.parseHexBinary(digest)
                );
    }
}
