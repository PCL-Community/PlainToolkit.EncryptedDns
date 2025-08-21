using PlainToolkit.EncryptedDns;
namespace PlainDnsClientTest;

public class Tests
{
    /// <summary>
    /// DNS 报文解析测试
    /// </summary>
    [Test]
    public void ParseDnsMessageTest()
    {
        var data = File.ReadAllBytes("response");
        var query = File.ReadAllBytes("dnsv4.bin");
        var result = Utils.ParseDnsMessage(query, data);
        foreach(var ip in result.AddressList ?? [])
        {
            Console.WriteLine(ip.Address.ToString());
            //Console.WriteLine(ip.TimeToLive);
            Console.WriteLine(ip.Type);
        }
    }
    /// <summary>
    /// DNS 查询报文生成测试
    /// </summary>
    [Test]
    public void MakeQuery()
    {
        File.WriteAllBytes("dns4.bin",Utils.GetDnsMessage("boximengling.luotianyi-0712.top",IPAddressType.IPv4));
        
        File.WriteAllBytes("dns6.bin",Utils.GetDnsMessage("boximengling.luotianyi-0712.top",IPAddressType.IPv6));
    }
    /// <summary>
    /// DoT 查询测试
    /// </summary>
    [Test]
    public void StartDoTQueryTest()
    {
        
        DoTClient.DoTAddress = "223.5.5.5";
        var result = DoTClient.SendDnsQueryAsync("boximengling.luotianyi-0712.top").GetAwaiter().GetResult();
        Console.WriteLine(result.ipv4Query.Status);
        Console.WriteLine(result.ipv6Query.Status);
        Console.WriteLine(result.ipv4Query.AddressList?.Count ?? 0);
        Console.WriteLine(result.ipv6Query.AddressList?.Count ?? 0);
        Console.WriteLine(result.ipv4Query.CName);
        Console.WriteLine(result.ipv6Query.CName);
        foreach(var ip in result.ipv4Query.AddressList ?? [])
        {
            Console.WriteLine(ip.Address.ToString());
            Console.WriteLine(ip.Type);
        }
        foreach(var ip in result.ipv6Query.AddressList ?? [])
        {
            Console.WriteLine(ip.Address.ToString());
            Console.WriteLine(ip.ExpiredAt);
            Console.WriteLine(ip.Type);
        }
        
    }
    /// <summary>
    /// DoH 查询测试
    /// </summary>
    [Test]
    public void StartDoHQueryTest()
    {
        DoHClient.DoHAddress = "https://223.5.5.5/dns-query";
        var result = DoHClient.SendDnsQueryAsync("blog.tangge233.top").GetAwaiter().GetResult();
        Console.WriteLine(result.ipv4Query.Status);
        Console.WriteLine(result.ipv6Query.Status);
        Console.WriteLine(result.ipv4Query.AddressList?.Count ?? 0);
        Console.WriteLine(result.ipv6Query.AddressList?.Count ?? 0);
        Console.WriteLine(result.ipv4Query.CName);
        Console.WriteLine(result.ipv6Query.CName);
        foreach(var ip in result.ipv4Query.AddressList ?? [])
        {
            Console.WriteLine(ip.Address.ToString());
            Console.WriteLine(ip.ExpiredAt);
            Console.WriteLine(ip.Type);
        }
        foreach(var ip in result.ipv6Query.AddressList ?? [])
        {
            Console.WriteLine(ip.Address.ToString());
            Console.WriteLine(ip.ExpiredAt);
            Console.WriteLine(ip.Type);
        }
    }
    /// <summary>
    /// DoT & DoH 查询超时测试
    /// </summary>
    [Test]
    public void TimeoutTest()
    {
        DoTClient.DoTAddress = "223.5.5.5";
        DoHClient.DoHAddress = "https://223.5.5.5/dns-query";
        var result = DoHClient.SendDnsQueryAsync("github.com",TimeSpan.FromMicroseconds(100)).GetAwaiter().GetResult();
        Console.WriteLine(result.ipv4Query.Status);
        Console.WriteLine(result.ipv6Query.Status);
        result = DoTClient.SendDnsQueryAsync("github.com",TimeSpan.FromMicroseconds(100)).GetAwaiter().GetResult();
        Console.WriteLine(result.ipv4Query.Status);
        Console.WriteLine(result.ipv6Query.Status);
    }
    /// <summary>
    /// 事务 ID 匹配测试
    /// </summary>
    [Test]
    public void ParseDnsMessageWithMismatchTest()
    {
        var data = File.ReadAllBytes("response");
        var query = File.ReadAllBytes("dns4.bin");
        var result = Utils.ParseDnsMessage(query, data);
        Console.WriteLine(result.Status);
    }
    
    // 以下测试必须失败
    
    /// <summary>
    /// DoH 协议安全性测试
    /// </summary>
    [Test]
    public void DoHInvalidValueHttpTest() => DoHClient.DoHAddress = "http://localhost/dns-query";
    /// <summary>
    /// DoH 无效协议测试
    /// </summary>
    [Test]
    public void DoHInvalidValueSchemaTest() => DoHClient.DoHAddress = "tcp://localhost/dns-query";
    /// <summary>
    /// DoH 仅空格地址测试
    /// </summary>
    [Test]
    public void DoHInvalidValueWhiteSpaceTest() => DoHClient.DoHAddress = "      ";
    /// <summary>
    /// DoH 空地址测试
    /// </summary>
    [Test]
    public void DoHInvalidValueEmptyeTest() => DoHClient.DoHAddress = "";
    /// <summary>
    /// DoT 端口号有效性测试
    /// </summary>
    [Test]
    public void DoTInvalidValueOutOfMaxPortTest() => DoTClient.DoTPort = 65536;
}
