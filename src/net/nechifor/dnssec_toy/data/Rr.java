package net.nechifor.dnssec_toy.data;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;
import net.nechifor.dnssec_toy.util.Util;

public class Rr
{
    public static final HashMap<String, Integer> typeCodeNumber =
            new HashMap<String, Integer>();
    public static final HashMap<Integer, String> typeCodeString =
            new HashMap<Integer, String>();


    public String name;
    public String type;
    public String theClass;
    public long ttl;
    public RData rData;

    static
    {
        typeCodeNumber.put("A", 1);
        typeCodeNumber.put("NS", 2);
        typeCodeNumber.put("SOA", 6);
        typeCodeNumber.put("MX", 15);
        typeCodeNumber.put("DS", 43);
        typeCodeNumber.put("RRSIG", 46);
        typeCodeNumber.put("NSEC", 47);
        typeCodeNumber.put("DNSKEY", 48);
        typeCodeString.put(1, "A");
        typeCodeString.put(2, "NS");
        typeCodeString.put(6, "SOA");
        typeCodeString.put(15, "MX");
        typeCodeString.put(43, "DS");
        typeCodeString.put(46, "RRSIG");
        typeCodeString.put(47, "NSEC");
        typeCodeString.put(48, "DNSKEY");
    }

    public Rr()
    {
    }

    public Rr(String s)
    {
        String[] split = s.split(" ");
        if (split.length < 5)
        {
            System.out.printf("Invalid RR String: '%s'.\n", s);
            System.exit(1);
        }

        this.name = split[0];
        this.type = split[1];
        this.theClass = split[2];
        this.ttl = Long.parseLong(split[3]);

        String joined = Util.join(split, " ", 4);

        if (this.type.equals("SOA"))
            this.rData = new RDataSoa(joined);
        else if (this.type.equals("NS"))
            this.rData = new RDataNs(joined);
        else if (this.type.equals("A"))
            this.rData = new RDataA(joined);
        else if (this.type.equals("MX"))
            this.rData = new RDataMx(joined);
        else if (this.type.equals("DS"))
            this.rData = new RDataDs(joined);
        else if (this.type.equals("RRSIG"))
            this.rData = new RDataRrSig(joined);
        else if (this.type.equals("NSEC"))
            this.rData = new RDataNsec(joined);
        else if (this.type.equals("DNSKEY"))
            this.rData = new RDataDnsKey(joined);
    }

    public static Rr fromBytes(ArrayList<Byte> b)
    {
        Rr ret = new Rr();

        ret.name = Util.getDomainFromByteArrayList(b);
        ret.type = typeCodeString.get(Util.getShortFromByteArrayList(b));
        if (Util.getShortFromByteArrayList(b) != 1)
            throw new RuntimeException("Only IN supported.");
        ret.theClass = "IN";
        ret.ttl = Util.getIntFromByteArrayList(b);

        int rDataLength = Util.getShortFromByteArrayList(b);

        ArrayList<Byte> rest = new ArrayList<Byte>();

        for (int i = 0; i < rDataLength; i++)
            rest.add(b.remove(0));

        if (ret.type.equals("SOA"))
            ret.rData = RDataSoa.fromBytes(rest);
        else if (ret.type.equals("NS"))
            ret.rData = RDataNs.fromBytes(rest);
        else if (ret.type.equals("A"))
            ret.rData = RDataA.fromBytes(rest);
        else if (ret.type.equals("MX"))
            ret.rData = RDataMx.fromBytes(rest);
        else if (ret.type.equals("DS"))
            ret.rData = RDataDs.fromBytes(rest);
        else if (ret.type.equals("RRSIG"))
            ret.rData = RDataRrSig.fromBytes(rest);
        else if (ret.type.equals("NSEC"))
            ret.rData = RDataNsec.fromBytes(rest);
        else if (ret.type.equals("DNSKEY"))
            ret.rData = RDataDnsKey.fromBytes(rest);

        return ret;
    }

    @Override
    public String toString()
    {
        return String.format("%s %s %s %d %s", name, type, theClass, ttl,
                rData);
    }

    public byte[] toBytes()
    {
        if (!theClass.equals("IN"))
            throw new RuntimeException("Only IN supported.");

        byte[] p1 = Util.domainToBytes(name);
        byte[] p2 = Util.shortToBytes(typeCodeNumber.get(type));
        byte[] p3 = Util.shortToBytes(1);
        byte[] p4 = Util.intToBytes(ttl);
        byte[] p6 = rData.toBytes(); // p6 [sic]
        byte[] p5 = Util.shortToBytes(p6.length);

        return Util.catBytes(p1, p2, p3, p4, p5, p6);
    }

    public static ArrayList<Rr> loadFromFile(File file)
    {
        ArrayList<Rr> ret = new ArrayList<Rr>();

        try
        {
            Scanner scanner = new Scanner(file);

            while (scanner.hasNextLine())
            {
                String line = scanner.nextLine().trim().replaceAll(" +", " ");
                ret.add(new Rr(line));
            }
        }
        catch (FileNotFoundException ex)
        {
            ex.printStackTrace();
            System.exit(1);
        }

        return ret;
    }
}