package net.nechifor.dnssec_toy.data;

import java.util.ArrayList;
import net.nechifor.dnssec_toy.util.Util;

public class RDataNsec extends RData
{
    public String nextDomainName;
    public byte[] typeBitMaps = new byte[32];

    public RDataNsec()
    {
    }
    
    public RDataNsec(String s)
    {
        String[] split = s.split(" ");
        this.nextDomainName = split[0];
        
        for (int i = 1; i < split.length; i++)
            setBitType(split[i], true);
    }

    public static RDataNsec fromBytes(ArrayList<Byte> b)
    {
        RDataNsec ret = new RDataNsec();

        ret.nextDomainName = Util.getDomainFromByteArrayList(b);

        int size = b.size();
        for (int i = 0; i < size; i++)
            ret.typeBitMaps[i] = b.get(i);

        return ret;
    }

    @Override
    public String toString()
    {
        return nextDomainName + " " + allBitTypes();
    }

    @Override
    public byte[] toBytes()
    {
        return Util.catBytes(Util.domainToBytes(nextDomainName),
                Util.cropByteArray(typeBitMaps));
    }

    final public void setBitType(String type, boolean value)
    {
        Util.setBit(typeBitMaps, Rr.typeCodeNumber.get(type), value);
    }

    public boolean getBitType(String type)
    {
        return Util.getBit(typeBitMaps, Rr.typeCodeNumber.get(type));
    }

    public String allBitTypes()
    {
        StringBuilder ret = new StringBuilder();

        for (String type : Rr.typeCodeNumber.keySet())
            if (getBitType(type))
                ret.append(type).append(" ");

        String retu = ret.toString();
        return retu.substring(0, retu.length() - 1);
    }
}
