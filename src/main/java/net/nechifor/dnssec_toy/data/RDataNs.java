package net.nechifor.dnssec_toy.data;

import java.util.ArrayList;
import net.nechifor.dnssec_toy.util.Util;

public class RDataNs extends RData
{
    public String nsDName;
    public int port; // Not standard. :)

    private RDataNs()
    {
    }

    public RDataNs(String s)
    {
        String[] split = s.split(" ");
        this.nsDName = split[0];
        this.port = Integer.parseInt(split[1]);
    }

    public static RDataNs fromBytes(ArrayList<Byte> b)
    {
        RDataNs ret = new RDataNs();

        ret.nsDName = Util.getDomainFromByteArrayList(b);
        ret.port = Util.getShortFromByteArrayList(b);

        return ret;
    }

    @Override
    public String toString()
    {
        return String.format("%s %d", nsDName, port);
    }

    @Override
    public byte[] toBytes()
    {
        return Util.catBytes(Util.domainToBytes(nsDName),
                Util.shortToBytes(port));
    }
}
