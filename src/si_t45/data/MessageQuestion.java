package si_t45.data;

import java.util.ArrayList;
import si_t45.util.Util;

public class MessageQuestion
{
    public String qname;
    public String qtype;
    public String qclass;

    public MessageQuestion()
    {
    }

    public byte[] toBytes()
    {
        if (!qclass.equals("IN"))
            throw new RuntimeException("Only IN supported.");
        return Util.catBytes(Util.domainToBytes(qname),
                Util.shortToBytes(Rr.typeCodeNumber.get(qtype)),
                Util.shortToBytes(1));
    }

    public static MessageQuestion fromBytes(ArrayList<Byte> b)
    {
        MessageQuestion ret = new MessageQuestion();

        ret.qname = Util.getDomainFromByteArrayList(b);
        ret.qtype = Rr.typeCodeString.get(Util.getShortFromByteArrayList(b));
        int c = Util.getShortFromByteArrayList(b);
        if (c != 1)
            throw new RuntimeException("Only IN supported.");
        ret.qclass = "IN";

        return ret;
    }

    @Override
    public String toString()
    {
        return qname + " " + qtype + " " + qclass;
    }
}
