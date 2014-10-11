package net.nechifor.dnssec_toy.logic;

import java.util.Comparator;

public class DomainComparator implements Comparator
{
    public int compare(Object o1, Object o2)
    {
        String a = (String) o1;
        String b = (String) o2;
        String[] aSplit = a.toLowerCase().split("\\.", -1);
        String[] bSplit = b.toLowerCase().split("\\.", -1);

        int min = aSplit.length;
        if (bSplit.length < min)
            min = bSplit.length;

        for (int i = 0; i < min; i++)
        {
            String la = aSplit[aSplit.length - 1 -i];
            String lb = bSplit[bSplit.length - 1 -i];

            int comp = la.compareTo(lb);
            if (comp != 0)
                return comp;
        }

        return new Integer(aSplit.length).compareTo(bSplit.length);
    }
}