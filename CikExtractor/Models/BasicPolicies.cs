namespace CikExtractor.Models;

public class BasicPolicies
{
    public bool LeaseRequired;
    public bool IsPrimary;
    public bool Expired;
    public bool IsUnlock;

    public BasicPolicies(ushort packed)
    {
        LeaseRequired = (packed & 1) == 1;
        IsPrimary = (packed & 2) == 1;
        Expired = (packed & 4) == 1;
        IsUnlock = (packed & 8) == 1;
    }
}