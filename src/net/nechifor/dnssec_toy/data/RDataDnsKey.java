package net.nechifor.dnssec_toy.data;

import java.util.ArrayList;
import javax.xml.bind.DatatypeConverter;
import net.nechifor.dnssec_toy.util.Util;

public class RDataDnsKey extends RData
{
    public int flags;
    public short protocol;
    public short algorithm;
    public byte[] publicKey;

    public RDataDnsKey()
    {
    }

    public RDataDnsKey(String s)
    {
        String[] split = s.split(" ");
        this.flags = Integer.parseInt(split[0]);
        if (!split[1].equals("3"))
            throw new RuntimeException("Only 3 is possible.");
        this.protocol = 3;
        if (!split[2].equals("5"))
            throw new RuntimeException("I've only implemented 5 (RSA/SHA-1).");
        this.algorithm = 5;
        this.publicKey = DatatypeConverter.parseBase64Binary(split[3]);
    }

    public static RDataDnsKey fromBytes(ArrayList<Byte> b)
    {
        RDataDnsKey ret = new RDataDnsKey();

        ret.flags = Util.getShortFromByteArrayList(b);
        ret.protocol = Util.getByteFromByteArrayList(b);
        ret.algorithm = Util.getByteFromByteArrayList(b);
        int size = b.size();
        ret.publicKey = new byte[size];
        for (int i = 0; i < size; i++)
            ret.publicKey[i] = b.remove(0);

        return ret;
    }

    @Override
    public String toString()
    {
        return flags + " " + protocol + " " + algorithm + " " +
                DatatypeConverter.printBase64Binary(publicKey);
    }

    @Override
    public byte[] toBytes()
    {
        return Util.catBytes(Util.shortToBytes(flags),
                Util.byteToBytes(protocol),
                Util.byteToBytes(algorithm),
                publicKey);
    }

    public boolean isZoneKey()
    {
        if ((flags & (1 << 8)) > 0) // 8 = 7 in reverse order.
            return true;
        else
            return false;
    }

    public void setZoneKey(boolean value)
    {
        if (value)
            flags |= (1 << 8); // 8 = 7 in reverse order.
        else
            flags &= ~(1 << 8); // 8 = 7 in reverse order.
    }

    // i.e. isKeySigningKey()
    public boolean isSecureEntryPoint()
    {
        if ((flags & (1 << 0)) > 0) // 0 = 15 in reverse order.
            return true;
        else
            return false;
    }

    public void setSecureEntryPoint(boolean value)
    {
        if (value)
            flags |= (1 << 0); // 0 = 15 in reverse order.
        else
            flags &= ~(1 << 0); // 0 = 15 in reverse order.
    }

    public int calculateKeyTag()
    {
        byte[] key = toBytes();
        long ac = 0;

        for (int i = 0; i < key.length; i++)
            ac += ((i & 1) > 0) ? key[i] : key[i] << 8;

        ac += (ac >> 16) & 0xffff;
        return (int)(ac & 0xffff);
    }
}