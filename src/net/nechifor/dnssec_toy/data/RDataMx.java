package net.nechifor.dnssec_toy.data;

import java.util.ArrayList;
import net.nechifor.dnssec_toy.util.Util;

public class RDataMx extends RData
{
    public int preference;
    public String exchange;

    private RDataMx()
    {
    }

    public RDataMx(String s)
    {
        String[] split = s.split(" ");
        this.preference = Integer.parseInt(split[0]);
        this.exchange = split[1];
    }

    public static RDataMx fromBytes(ArrayList<Byte> b)
    {
        RDataMx ret = new RDataMx();
        
        ret.preference = Util.getShortFromByteArrayList(b);
        ret.exchange = Util.getDomainFromByteArrayList(b);
        
        return ret;
    }

    @Override
    public String toString()
    {
        return String.format("%d %s", preference, exchange);
    }

    @Override
    public byte[] toBytes()
    {
        return Util.catBytes(Util.shortToBytes(preference),
                Util.domainToBytes(exchange));
    }
}
