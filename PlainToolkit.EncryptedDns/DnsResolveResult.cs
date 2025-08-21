using System.Net;

namespace PlainToolkit.EncryptedDns;



public class DnsResolveResult
{
    public DnsResolveStatus Status { get; set; }
    public List<NetAddress>? AddressList { get; set; }
    public string? CName { get; set; } // 只供内部递归使用，不对外暴露
}

public enum DnsResolveStatus
{
    /// <summary>
    /// 成功
    /// </summary>
    Success,
    /// <summary>
    /// 未找到目标主机
    /// </summary>
    HostNotFound,
    /// <summary>
    /// 无效的 DNS 响应报文
    /// </summary>
    InvalidResponse,
    /// <summary>
    /// DNS 服务器错误
    /// </summary>
    ServerError,
    /// <summary>
    /// 格式错误
    /// </summary>
    FormattedError,
    /// <summary>
    /// 拒绝查询请求
    /// </summary>
    Refuse,
    /// <summary>
    /// 不支持
    /// </summary>
    Unsupported,
    /// <summary>
    /// 事务 ID 不匹配
    /// </summary>
    TransactionIdMismatched,
    /// <summary>
    /// 内部阻止（设置 IPv4Only 或者 IPv6Only）
    /// </summary>
    InternalBlocked,
    /// <summary>
    /// CNAME 重定向（不完全解析）
    /// </summary>
    CNameRedirect
}

public enum QueryOptions
{
    IPv6Only,
    IPv4Only,
    Mixed
}