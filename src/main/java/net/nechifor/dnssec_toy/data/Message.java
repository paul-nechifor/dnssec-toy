package net.nechifor.dnssec_toy.data;

import java.util.ArrayList;
import net.nechifor.dnssec_toy.util.Util;

public class Message
{
    public MessageHeader header;
    public MessageQuestion question;
    public ArrayList<Rr> answer;
    public ArrayList<Rr> authority;
    public ArrayList<Rr> additional;

    public Message()
    {
        header = new MessageHeader();
        question = new MessageQuestion();
        answer = new ArrayList<Rr>();
        authority = new ArrayList<Rr>();
        additional = new ArrayList<Rr>();
    }

    public byte[] toBytes()
    {
        header.qdcount = 1;
        header.ancount = answer.size();
        header.nscount = authority.size();
        header.arcount = additional.size();

        byte[] ret = header.toBytes();
        ret = Util.catBytes(ret, question.toBytes());

        for (Rr rr : answer)
            ret = Util.catBytes(ret, rr.toBytes());
        for (Rr rr : authority)
            ret = Util.catBytes(ret, rr.toBytes());
        for (Rr rr : additional)
            ret = Util.catBytes(ret, rr.toBytes());

        return ret;
    }

    public static Message fromBytes(ArrayList<Byte> b)
    {
        Message ret = new Message();

        ret.header = MessageHeader.fromBytes(b);
        ret.question = MessageQuestion.fromBytes(b);

        for (int i = 0; i < ret.header.ancount; i++)
            ret.answer.add(Rr.fromBytes(b));
        for (int i = 0; i < ret.header.nscount; i++)
            ret.authority.add(Rr.fromBytes(b));
        for (int i = 0; i < ret.header.arcount; i++)
            ret.additional.add(Rr.fromBytes(b));

        return ret;
    }

    @Override
    public String toString()
    {
        String ret = "";
        ret += "+--- Header ------------------------------------------------\n";
        ret += "| " + header.toString() + "\n";
        ret += "+--- Question ----------------------------------------------\n";
        ret += "| " + question.toString() + "\n";
        ret += "+--- Answer ------------------------------------------------\n";
        for (Rr rr : answer)
            ret += "| " + rr.toString() + "\n";
        ret += "+--- Authority ---------------------------------------------\n";
        for (Rr rr : authority)
            ret += "| " + rr.toString() + "\n";
        ret += "+--- Additional --------------------------------------------\n";
        for (Rr rr : additional)
            ret += "| " + rr.toString() + "\n";
        ret += "+-----------------------------------------------------------\n";

        return ret;
    }
}
