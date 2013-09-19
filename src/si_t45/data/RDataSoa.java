package si_t45.data;

import java.util.ArrayList;
import si_t45.util.Util;

public class RDataSoa extends RData
{
    public String mName;
    public String rName;
    public long serial;
    public long refresh;
    public long retry;
    public long expire;
    public long minimum;

    private RDataSoa()
    {
    }

    public RDataSoa(String s)
    {
        String[] split = s.split(" ");
        this.mName = split[0];
        this.rName = split[1];
        this.serial = Long.parseLong(split[2]);
        this.refresh = Long.parseLong(split[3]);
        this.retry = Long.parseLong(split[4]);
        this.expire = Long.parseLong(split[5]);
        this.minimum = Long.parseLong(split[6]);
    }

    public static RDataSoa fromBytes(ArrayList<Byte> b)
    {
        RDataSoa ret = new RDataSoa();
        
        ret.mName = Util.getDomainFromByteArrayList(b);
        ret.rName = Util.getDomainFromByteArrayList(b);
        ret.serial = Util.getIntFromByteArrayList(b);
        ret.refresh = Util.getIntFromByteArrayList(b);
        ret.retry = Util.getIntFromByteArrayList(b);
        ret.expire = Util.getIntFromByteArrayList(b);
        ret.minimum = Util.getIntFromByteArrayList(b);

        return ret;
    }

    @Override
    public String toString()
    {
        return String.format("%s %s %d %d %d %d %d", mName, rName, serial,
                refresh, retry, expire, minimum);
    }

    @Override
    public byte[] toBytes()
    {
        return Util.catBytes(Util.domainToBytes(mName),
                Util.domainToBytes(rName),
                Util.intToBytes(serial),
                Util.intToBytes(refresh),
                Util.intToBytes(retry),
                Util.intToBytes(expire),
                Util.intToBytes(minimum));
    }
}
