package net.nechifor.dnssec_toy.util;

import java.util.ArrayList;

public class Util
{
    public static String join(String[] s, String glue, int start)
    {
        StringBuilder out = new StringBuilder();
        out.append(s[start]);
        for (int i = start + 1; i < s.length; i++)
            out.append(glue).append(s[i]);

        return out.toString();
    }

    public static byte[] domainToBytes(String domain)
    {
        if (domain.equals("."))
            return new byte[] {(byte) 0};

        String[] split = domain.split("\\.", -1);
        byte[] ret = new byte[domain.length() + 1];

        int k = 0;
        for (int i = 0; i < split.length; i++)
        {
            byte[] bytes = split[i].getBytes();
            if (bytes.length >= 64)
                throw new RuntimeException("Domain label '" + split[i] +
                        "' is too long.");

            ret[k++] = (byte) bytes.length;
            for (int j = 0; j < bytes.length; j++)
                ret[k++] = bytes[j];
        }

        return ret;
    }

    public static String bytesToDomain(byte[] bytes)
    {
        if (bytes[0] == 0)
            return ".";

        StringBuilder ret = new StringBuilder(bytes.length);
        int k = 0;

        while (true)
        {
            byte length = bytes[k++];
            if (length == 0)
                break;
            ret.append(new String(bytes, k, length));
            ret.append(".");
            k += length;
        }

        return ret.toString();
    }

    public static String getDomainFromByteArrayList(ArrayList<Byte> b)
    {
        int index = b.indexOf(new Byte((byte)0));
        byte[] bytes = new byte[index + 1];
        for (int i = 0; i <= index; i++)
            bytes[i] = b.remove(0);

        return bytesToDomain(bytes);
    }

    public static byte[] byteToBytes(short n)
    {
        if (n > 0xff)
            throw new RuntimeException("Number " + n + " can't fit.");

        return new byte[] {(byte) n};
    }

    public static short bytesToByte(byte[] b)
    {
        return b[0];
    }

    public static short getByteFromByteArrayList(ArrayList<Byte> b)
    {
        return b.remove(0);
    }

    public static byte[] shortToBytes(int n)
    {
        if (n > 0xffff)
            throw new RuntimeException("Number " + n + " can't fit.");

        // Big Endian.
        return new byte[]
                {
                    (byte) ((n >>> 8) & 0xff),
                    (byte) (n & 0xff)
                };
    }

    public static int bytesToShort(byte[] b)
    {
        // Big Endian.
        return ((b[0] & 0xff) << 8) + (b[1] & 0xff);
    }

    public static int getShortFromByteArrayList(ArrayList<Byte> b)
    {
        // Big Endian.
        return bytesToShort(new byte[]{b.remove(0), b.remove(0)});
    }

    public static byte[] intToBytes(long n)
    {
        if (n > 0xffffffffL)
            throw new RuntimeException("Number " + n + " can't fit.");

        // Big Endian.
        return new byte[]
                {
                    (byte) ((n >> 24) & 0xff),
                    (byte) ((n >> 16) & 0xff),
                    (byte) ((n >> 8) & 0xff),
                    (byte) (n & 0xff)
                };
    }

    public static long bytesToInt(byte[] b)
    {
        // Big Endian.
        return ((b[0] & 0xffL) << 24) |
                ((b[1] & 0xffL) << 16) |
                ((b[2] & 0xffL) << 8) |
                (b[3] & 0xffL);
    }

    public static long getIntFromByteArrayList(ArrayList<Byte> b)
    {
        return bytesToInt(new byte[]{b.remove(0), b.remove(0), b.remove(0),
                b.remove(0)});
    }

    public static byte[] catBytes(byte[] ... b)
    {
        int totalLength = 0;

        for (int i = 0; i < b.length; i++)
            totalLength += b[i].length;

        byte[] ret = new byte[totalLength];
        int k = 0;

        for (int i = 0; i < b.length; i++)
        {
            System.arraycopy(b[i], 0, ret, k, b[i].length);
            k += b[i].length;
        }

        return ret;
    }

    public static ArrayList<Byte> byteArrayList(byte[] bytes)
    {
        ArrayList<Byte> ret = new ArrayList<Byte>();

        for (int i = 0; i < bytes.length; i++)
            ret.add(bytes[i]);

        return ret;
    }

    public static byte[] byteArray(ArrayList<Byte> b)
    {
        byte[] ret = new byte[b.size()];
        for (int i = 0; i < ret.length; i++)
            ret[i] = b.get(i);
        return ret;
    }

    public static int randint(int min, int max)
    {
        return min + (int)(Math.random() * ((max - min) + 1));
    }

    public static void setBit(byte[] bytes, int order, boolean value)
    {
        int indexOctet = order / 8;
        int indexBit = order % 8;
        
        if (value)
            bytes[indexOctet] |= (1 << indexBit);
        else
            bytes[indexOctet] &= ~(1 << indexBit);
    }

    public static boolean getBit(byte[] bytes, int order)
    {
        return (bytes[order / 8] & (1 << (order%8))) > 0;
    }

    // Remove all the bytes at the end which are 0.
    public static byte[] cropByteArray(byte[] bytes)
    {
        int i;
        for (i = bytes.length - 1; i >= 0; i--)
            if (bytes[i] != 0)
                break;

        byte[] ret = new byte[i + 1];
        System.arraycopy(bytes, 0, ret, 0, ret.length);
        return ret;
    }

    public static String padRight(String s, int n)
    {
         return String.format("%1$-" + n + "s", s);
    }

    public static String padLeft(String s, int n)
    {
        return String.format("%1$#" + n + "s", s);
    }

}
