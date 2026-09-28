namespace NGPVP.Shared;

public enum FindingSeverity
{
    Clean,
    Known,
    Suspicious,
    Detected
}

public sealed record RegisterRequest(string Hostname, string Version);
public sealed record RegisterResponse(string PlayerId, string AgentToken);
public sealed record ScanProgressDto(int Progress, string Stage);

public sealed record PlayerStatusDto(
    string Id, string Player, bool Connected, bool Started, bool Completed,
    DateTime ConnectedAtUtc, DateTime? StartedAtUtc, DateTime? CompletedAtUtc,
    int Progress, string Stage);

public sealed record ScanItemDto(
    string Category,
    string Name,
    string? Path,
    string? Publisher,
    string? Signature,
    string? Sha256,
    FindingSeverity Severity,
    string Reason,
    DateTime TimestampUtc);

public sealed record ScanReportDto(
    string CheckId,
    string PlayerId,
    DateTime StartedAtUtc,
    DateTime CompletedAtUtc,
    List<ScanItemDto> Results);

public sealed record SessionStatusDto(
    string Id,
    string Player,
    bool Connected,
    bool Started,
    bool Completed,
    string? CheckId,
    DateTime ConnectedAtUtc,
    DateTime? StartedAtUtc,
    DateTime? CompletedAtUtc,
    int Progress,
    string Stage,
    List<ScanItemDto> Results);

// Staff access management
public sealed record StaffLoginRequest(string Name, string Code);
public sealed record StaffLoginResponse(string StaffId, string Name, string Token, bool IsAdmin, DateTime? ExpiresAtUtc);
public sealed record StaffAccessStatusDto(bool Active, DateTime? UntilUtc, string StaffId, string Name, bool IsAdmin);
public sealed record GrantStaffAccessRequest(string Name, int DurationMinutes);
public sealed record GrantStaffAccessResponse(string StaffId, string Name, string AccessCode, DateTime ExpiresAtUtc);
public sealed record StaffAccessDto(string StaffId, string Name, bool Active, bool Revoked, DateTime GrantedAtUtc, DateTime? ExpiresAtUtc, DateTime? LastLoginUtc, DateTime? LastSeenUtc, int ActiveSessions, bool IsAdmin);
public sealed record StaffAuditDto(DateTime TimestampUtc, string Action, string StaffId, string Name, string Details);
public sealed record StaffExtendRequest(int DurationMinutes);
