namespace CikExtractor.Models;

[Flags]
public enum BasicPolicies : ushort
{
    LeaseRequired = 1 << 0,
    IsPrimary = 1 << 1,
    Expired = 1 << 2,
    IsUnlock = 1 << 3
}