using System.Net;

namespace PlainToolkit.EncryptedDns;

public class NetAddress
{
    public required IPAddress Address;
    public DateTime ExpiredAt;
    public IPAddressType Type;
}

public enum IPAddressType
{
    IPv4,
    IPv6,
    Unknown
}