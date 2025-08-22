using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace PlainToolkit.EncryptedDns;

public static class Utils
{
    private static readonly byte[] TypeA = [0x00, 0x01];
    private static readonly byte[] TypeAaaa = [0x00, 0x1C];
    private static readonly byte[] ClassIn = [0x00, 0x01];
    private static readonly byte[] DnsFlagsAndCounts =
    [
        0x01, 0x00, // RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00  // ARCOUNT
    ];

    private static readonly IdnMapping Idn = new();

    private static byte[] GetRandomByte(int byteCount) => RandomNumberGenerator.GetBytes(byteCount);

    public static byte[] GetDnsMessage(string address, IPAddressType type)
    {
        var dnsMessage = new List<byte>();
        dnsMessage.AddRange(GetRandomByte(2)); // Transaction ID
        dnsMessage.AddRange(DnsFlagsAndCounts);

        // PunyCode
        var i18NAddr = Idn.GetAscii(address);
        foreach (var label in i18NAddr.Split('.'))
        {
            if (label.Length is < 1 or > 63)
                throw new FormatException("地址标签长度不应多于 63 个字符或少于 1 个字符");

            var domainBytes = Encoding.ASCII.GetBytes(label);
            dnsMessage.Add((byte)domainBytes.Length);
            dnsMessage.AddRange(domainBytes);
        }

        dnsMessage.Add(0x00); // 结束段

        // QTYPE + QCLASS
        dnsMessage.AddRange(type switch
        {
            IPAddressType.IPv4 => TypeA,
            IPAddressType.IPv6 => TypeAaaa,
            IPAddressType.Unknown => throw new ArgumentException("无效的记录值"),
            _ => throw new NotImplementedException("暂不支持该记录值")
        });
        dnsMessage.AddRange(ClassIn);

        return dnsMessage.ToArray();
    }

    public static DnsResolveResult ParseDnsMessage(byte[] originalDnsMessage, byte[] receivedDnsMessage)
    {
        var rcode = receivedDnsMessage[3] & 0x0F;
        var result = new DnsResolveResult();

        // 事务 ID 校验
        var origId = (ushort)((originalDnsMessage[0] << 8) | originalDnsMessage[1]);
        var recvId = (ushort)((receivedDnsMessage[0] << 8) | receivedDnsMessage[1]);
        if (origId != recvId)
        {
            result.Status = DnsResolveStatus.TransactionIdMismatched;
            return result;
        }

        if ((receivedDnsMessage[2] & 0x80) == 0 || receivedDnsMessage.Length < 12)
        {
            result.Status = DnsResolveStatus.InvalidResponse;
            return result;
        }

        result.Status = rcode switch
        {
            1 => DnsResolveStatus.FormattedError,
            2 => DnsResolveStatus.ServerError,
            4 => DnsResolveStatus.Unsupported,
            5 => DnsResolveStatus.Refuse,
            _ => result.Status
        };

        int anCount = (receivedDnsMessage[6] << 8) | receivedDnsMessage[7];
        if (rcode == 3 || anCount == 0)
        {
            result.Status = DnsResolveStatus.HostNotFound;
            return result;
        }

        int offset = 12;

        // 跳过 Question
        int qdCount = (receivedDnsMessage[4] << 8) | receivedDnsMessage[5];
        for (int i = 0; i < qdCount; i++)
        {
            SkipDomainName(receivedDnsMessage, ref offset);
            offset += 4;
        }

        result.AddressList ??= [];

        // 保存可能的 CNAME 链
        string? lastCname = null;

        // 解析 Answer
        for (int i = 0; i < anCount; i++)
        {
            SkipDomainName(receivedDnsMessage, ref offset);

            ushort type = (ushort)((receivedDnsMessage[offset] << 8) | receivedDnsMessage[offset + 1]);
            offset += 2;

            ushort clazz = (ushort)((receivedDnsMessage[offset] << 8) | receivedDnsMessage[offset + 1]);
            offset += 2;

            uint ttl = (uint)((receivedDnsMessage[offset] << 24) |
                               (receivedDnsMessage[offset + 1] << 16) |
                               (receivedDnsMessage[offset + 2] << 8) |
                               receivedDnsMessage[offset + 3]);
            offset += 4;

            ushort rdLength = (ushort)((receivedDnsMessage[offset] << 8) | receivedDnsMessage[offset + 1]);
            offset += 2;

            if (offset + rdLength > receivedDnsMessage.Length)
            {
                result.Status = DnsResolveStatus.InvalidResponse;
                return result;
            }

            if (type == 1 || type == 28) // A / AAAA
            {
                var ip = new IPAddress(receivedDnsMessage.AsSpan(offset, rdLength));
                result.AddressList.Add(new NetAddress
                {
                    Address = ip,
                    ExpiredAt = DateTime.Now.AddSeconds(ttl),
                    Type = type == 1 ? IPAddressType.IPv4 : IPAddressType.IPv6
                });
                offset += rdLength;
            }
            else if (type == 5) // CNAME
            {
                int cnameOffset = offset;
                string cname = ReadDomainName(receivedDnsMessage, ref cnameOffset);
                lastCname = cname;

                // 注意：ReadDomainName 会自己更新 offset（基于 cnameOffset），
                // 我们这里要保证 offset 至少跳过整个 rdLength
                offset += rdLength;
            }
            else
            {
                // 跳过未知类型
                offset += rdLength;
            }
        }

        // ---- 后处理 ----
        if (result.AddressList.Count > 0)
        {
            if (lastCname != null)
                result.CName = lastCname; // 有 A/AAAA，顺便保存 CNAME
            result.Status = DnsResolveStatus.Success;
        }
        else if (lastCname != null)
        {
            result.CName = lastCname;
            result.Status = DnsResolveStatus.CNameRedirect; // 只有 CNAME 没有 IP
        }

        return result;
    }

    private static void SkipDomainName(byte[] message, ref int offset)
    {
        while (true)
        {
            if (offset >= message.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset exceeds message length.");

            byte len = message[offset];
            if (len == 0)
            {
                offset += 1;
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                offset += 2;
                break;
            }
            offset += 1 + len;
        }
    }

    private static string ReadDomainName(byte[] message, ref int offset)
    {
        var labels = new List<string>();
        int originalOffset = offset;
        bool jumped = false;

        while (true)
        {
            if (offset >= message.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));

            byte len = message[offset];

            if (len == 0)
            {
                offset++;
                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                int pointer = ((len & 0x3F) << 8) | message[offset + 1];
                if (!jumped)
                {
                    originalOffset = offset + 2;
                    jumped = true;
                }
                offset = pointer;
                continue;
            }

            offset++;
            if (offset + len > message.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));

            labels.Add(Encoding.ASCII.GetString(message, offset, len));
            offset += len;
        }

        if (jumped)
            offset = originalOffset;

        return string.Join(".", labels);
    }
}
