package net.nechifor.dnssec_toy.data;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class RDataA extends RData
{
    public String address;

    private RDataA()
    {
    }

    public RDataA(String s)
    {
        this.address = s;
    }

    @Override
    public String toString()
    {
        return address;
    }

    public static RDataA fromBytes(ArrayList<Byte> b)
    {
        RDataA ret = new RDataA();

        byte[] a = new byte[] {b.remove(0), b.remove(0), b.remove(0),
                b.remove(0)};
        try
        {
            ret.address = InetAddress.getByAddress(a).getHostAddress();
        }
        catch (UnknownHostException ex)
        {
            ex.printStackTrace();
            System.exit(1);
        }

        return ret;
    }

    @Override
    public byte[] toBytes()
    {
        try
        {
            return InetAddress.getByName(address).getAddress();
        }
        catch (UnknownHostException ex)
        {
            ex.printStackTrace();
            System.exit(1);
            return null;
        }
    }
}
