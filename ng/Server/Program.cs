using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NGPVP.Shared;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));
var app = builder.Build();
app.UseCors();

var sessions = new ConcurrentDictionary<string, Session>();
var staffKey = Environment.GetEnvironmentVariable("NGPVP_STAFF_KEY") ?? "ngpvpriouxa1";
var staffUntilRaw = Environment.GetEnvironmentVariable("NGPVP_STAFF_ACCESS_UNTIL");
var reportsDir = Path.Combine(AppContext.BaseDirectory, "reports");
Directory.CreateDirectory(reportsDir);

var staffAccounts = new ConcurrentDictionary<string, StaffAccount>();
var staffSessions = new ConcurrentDictionary<string, StaffSession>();
var staffAudit = new ConcurrentQueue<StaffAuditDto>();

void Audit(string action, string staffId, string name, string details)
{
    staffAudit.Enqueue(new StaffAuditDto(DateTime.UtcNow, action, staffId, name, details));
    while (staffAudit.Count > 500 && staffAudit.TryDequeue(out _)) { }
}

static string HashCode(string value)
{
    var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
    return Convert.ToHexString(bytes);
}

bool AdminAllowed(HttpRequest req)
    => req.Headers.TryGetValue("X-Staff-Key", out var supplied) && supplied.ToString() == staffKey &&
       (!DateTime.TryParse(staffUntilRaw, out var until) || DateTime.UtcNow <= until.ToUniversalTime());

StaffSession? ResolveStaff(HttpRequest req)
{
    if (AdminAllowed(req))
        return new StaffSession("MASTER-ADMIN", "MASTER ADMIN", true, null, DateTime.UtcNow);

    if (!req.Headers.TryGetValue("X-Staff-Token", out var token)) return null;
    if (!staffSessions.TryGetValue(token.ToString(), out var session)) return null;
    if (session.ExpiresAtUtc is DateTime expires && DateTime.UtcNow > expires)
    {
        staffSessions.TryRemove(token.ToString(), out _);
        return null;
    }
    if (session.Revoked) return null;
    if (staffAccounts.TryGetValue(session.StaffId, out var account) && (account.Revoked || (account.ExpiresAtUtc is DateTime aexp && DateTime.UtcNow > aexp)))
        return null;
    return session;
}

bool StaffAllowed(HttpRequest req) => ResolveStaff(req) is not null;

app.MapGet("/", () => Results.Text("PC CHECK NG Server OK"));

app.MapPost("/api/register", (RegisterRequest req) =>
{
    var id = "PLAYER-" + Random.Shared.Next(0x100000, 0xFFFFFF).ToString("X6");
    var token = Convert.ToHexString(Guid.NewGuid().ToByteArray());
    var s = new Session(id, id, token, DateTime.UtcNow);
    sessions[id] = s;
    return Results.Ok(new RegisterResponse(id, token));
});

app.MapPost("/api/staff/login", (StaffLoginRequest req) =>
{
    var name = string.IsNullOrWhiteSpace(req.Name) ? "STAFF" : req.Name.Trim();
    if (string.IsNullOrWhiteSpace(req.Code)) return Results.BadRequest(new { message = "ACCESS_CODE_REQUIRED" });

    if (req.Code == staffKey)
    {
        var token = "ADM-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(18));
        staffSessions[token] = new StaffSession("MASTER-ADMIN", name == "STAFF" ? "MASTER ADMIN" : name, true, DateTime.UtcNow.AddHours(12), DateTime.UtcNow);
        Audit("LOGIN", "MASTER-ADMIN", staffSessions[token].Name, "Administrator login");
        return Results.Ok(new StaffLoginResponse("MASTER-ADMIN", staffSessions[token].Name, token, true, staffSessions[token].ExpiresAtUtc));
    }

    var hash = HashCode(req.Code);
    var account = staffAccounts.Values.FirstOrDefault(x => x.CodeHash == hash && !x.Revoked && (!x.ExpiresAtUtc.HasValue || DateTime.UtcNow <= x.ExpiresAtUtc.Value));
    if (account is null) return Results.Unauthorized();

    account.LastLoginUtc = DateTime.UtcNow;
    account.LastSeenUtc = DateTime.UtcNow;
    var sessionToken = "STF-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(18));
    var expiry = account.ExpiresAtUtc ?? DateTime.UtcNow.AddHours(8);
    staffSessions[sessionToken] = new StaffSession(account.StaffId, account.Name, false, expiry, DateTime.UtcNow);
    account.ActiveSessions++;
    Audit("LOGIN", account.StaffId, account.Name, $"Session expires {expiry:O}");
    return Results.Ok(new StaffLoginResponse(account.StaffId, account.Name, sessionToken, false, expiry));
});

app.MapPost("/api/staff/logout", (HttpRequest req) =>
{
    if (req.Headers.TryGetValue("X-Staff-Token", out var token) && staffSessions.TryRemove(token.ToString(), out var session))
    {
        if (staffAccounts.TryGetValue(session.StaffId, out var account)) { account.ActiveSessions = Math.Max(0, account.ActiveSessions - 1); account.LastSeenUtc = DateTime.UtcNow; }
        Audit("LOGOUT", session.StaffId, session.Name, "Session closed");
    }
    return Results.Ok();
});

app.MapGet("/api/staff/status", (HttpRequest req) =>
{
    var staff = ResolveStaff(req);
    if (staff is null) return Results.Unauthorized();
    if (staffAccounts.TryGetValue(staff.StaffId, out var account)) account.LastSeenUtc = DateTime.UtcNow;
    return Results.Ok(new StaffAccessStatusDto(true, staff.ExpiresAtUtc, staff.StaffId, staff.Name, staff.IsAdmin));
});

app.MapGet("/api/staff/access", (HttpRequest req) =>
{
    if (!AdminAllowed(req)) return Results.Unauthorized();
    var now = DateTime.UtcNow;
    var list = staffAccounts.Values.OrderByDescending(x => x.LastLoginUtc ?? x.GrantedAtUtc).Select(x =>
        new StaffAccessDto(x.StaffId, x.Name, !x.Revoked && (!x.ExpiresAtUtc.HasValue || now <= x.ExpiresAtUtc.Value), x.Revoked, x.GrantedAtUtc, x.ExpiresAtUtc, x.LastLoginUtc, x.LastSeenUtc, x.ActiveSessions, false)).ToList();
    return Results.Ok(list);
});

app.MapGet("/api/staff/audit", (HttpRequest req) =>
{
    if (!AdminAllowed(req)) return Results.Unauthorized();
    return Results.Ok(staffAudit.Reverse().Take(250).ToList());
});

app.MapPost("/api/staff/access/grant", (GrantStaffAccessRequest req, HttpRequest httpReq) =>
{
    if (!AdminAllowed(httpReq)) return Results.Unauthorized();
    var name = string.IsNullOrWhiteSpace(req.Name) ? "STAFF" : req.Name.Trim();
    var duration = Math.Clamp(req.DurationMinutes, 5, 43200);
    var id = "STAFF-" + Random.Shared.Next(0x100000, 0xFFFFFF).ToString("X6");
    var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
    var account = new StaffAccount(id, name, HashCode(code), DateTime.UtcNow, DateTime.UtcNow.AddMinutes(duration));
    staffAccounts[id] = account;
    Audit("GRANT", id, name, $"Access granted until {account.ExpiresAtUtc:O}");
    return Results.Ok(new GrantStaffAccessResponse(id, name, code, account.ExpiresAtUtc!.Value));
});

app.MapPost("/api/staff/access/{id}/revoke", (string id, HttpRequest httpReq) =>
{
    if (!AdminAllowed(httpReq)) return Results.Unauthorized();
    if (!staffAccounts.TryGetValue(id, out var account)) return Results.NotFound();
    account.Revoked = true;
    foreach (var kv in staffSessions.Where(x => x.Value.StaffId == id).ToList()) staffSessions.TryRemove(kv.Key, out _);
    account.ActiveSessions = 0;
    Audit("REVOKE", id, account.Name, "Access revoked by administrator");
    return Results.Ok();
});

app.MapPost("/api/staff/access/{id}/extend", async (string id, HttpRequest httpReq) =>
{
    if (!AdminAllowed(httpReq)) return Results.Unauthorized();
    if (!staffAccounts.TryGetValue(id, out var account)) return Results.NotFound();
    var body = await httpReq.ReadFromJsonAsync<StaffExtendRequest>();
    var duration = Math.Clamp(body?.DurationMinutes ?? 60, 5, 43200);
    account.Revoked = false;
    account.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(duration);
    Audit("EXTEND", id, account.Name, $"Access extended until {account.ExpiresAtUtc:O}");
    return Results.Ok(new { account.ExpiresAtUtc });
});

app.MapGet("/api/sessions", (HttpRequest req) =>
{
    if (!StaffAllowed(req)) return Results.Unauthorized();
    var now = DateTime.UtcNow;
    var list = sessions.Values.Where(x => now - x.LastHeartbeatUtc < TimeSpan.FromSeconds(25)).OrderByDescending(x => x.ConnectedAtUtc).Select(x => x.ToPlayerStatus()).ToList();
    return Results.Ok(list);
});

app.MapPost("/api/session/{id}/start", (string id, HttpRequest req) =>
{
    if (!StaffAllowed(req)) return Results.Unauthorized();
    if (!sessions.TryGetValue(id, out var s)) return Results.NotFound();
    if (DateTime.UtcNow - s.LastHeartbeatUtc > TimeSpan.FromSeconds(25)) return Results.Conflict(new { message = "PLAYER_OFFLINE" });
    s.Started = true; s.Completed = false; s.Progress = 0; s.Stage = "QUEUED";
    s.CheckId = "CHK-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Random.Shared.Next(1000,9999);
    s.StartedAtUtc = DateTime.UtcNow; s.CompletedAtUtc = null; s.Results.Clear();
    return Results.Ok(new { s.CheckId });
});

app.MapGet("/api/session/{id}", (string id, HttpRequest req) =>
{
    if (!StaffAllowed(req)) return Results.Unauthorized();
    if (!sessions.TryGetValue(id, out var s)) return Results.NotFound();
    return Results.Ok(s.ToStatus());
});

app.MapGet("/api/session/{id}/command", (string id, HttpRequest req) =>
{
    if (!sessions.TryGetValue(id, out var s)) return Results.NotFound();
    if (!req.Headers.TryGetValue("X-Agent-Token", out var token) || token.ToString() != s.AgentToken) return Results.Unauthorized();
    return Results.Ok(new { start = s.Started && !s.Completed, checkId = s.CheckId });
});

app.MapPost("/api/session/{id}/progress", async (string id, HttpRequest req) =>
{
    if (!sessions.TryGetValue(id, out var s)) return Results.NotFound();
    if (!req.Headers.TryGetValue("X-Agent-Token", out var token) || token.ToString() != s.AgentToken) return Results.Unauthorized();
    var p = await req.ReadFromJsonAsync<ScanProgressDto>(); if (p is null) return Results.BadRequest();
    s.Progress = Math.Clamp(p.Progress, 0, 100); s.Stage = string.IsNullOrWhiteSpace(p.Stage) ? "SCANNING" : p.Stage.Trim(); s.LastHeartbeatUtc = DateTime.UtcNow;
    return Results.Ok();
});

app.MapPost("/api/session/{id}/results", async (string id, HttpRequest req) =>
{
    if (!sessions.TryGetValue(id, out var s)) return Results.NotFound();
    if (!req.Headers.TryGetValue("X-Agent-Token", out var token) || token.ToString() != s.AgentToken) return Results.Unauthorized();
    var report = await req.ReadFromJsonAsync<ScanReportDto>(); if (report is null) return Results.BadRequest();
    s.CheckId = report.CheckId; s.Results.Clear(); s.Results.AddRange(report.Results.Take(5000)); s.Completed = true; s.Started = true; s.Progress = 100; s.Stage = "COMPLETE"; s.CompletedAtUtc = report.CompletedAtUtc; s.LastHeartbeatUtc = DateTime.UtcNow;
    try { var file = Path.Combine(reportsDir, report.CheckId.Replace("..", "_").Replace("/", "_").Replace("\\", "_") + ".json"); File.WriteAllText(file, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true })); } catch { }
    return Results.Ok();
});

app.MapGet("/api/report/{checkId}", (string checkId, HttpRequest req) =>
{
    if (!StaffAllowed(req)) return Results.Unauthorized();
    var safe = checkId.Replace("..", "_").Replace("/", "_").Replace("\\", "_"); var file = Path.Combine(reportsDir, safe + ".json");
    return File.Exists(file) ? Results.Text(File.ReadAllText(file), "application/json") : Results.NotFound();
});

app.MapPost("/api/session/{id}/heartbeat", async (string id, HttpRequest req) =>
{
    if (!sessions.TryGetValue(id, out var s)) return Results.NotFound();
    if (!req.Headers.TryGetValue("X-Agent-Token", out var token) || token.ToString() != s.AgentToken) return Results.Unauthorized();
    s.LastHeartbeatUtc = DateTime.UtcNow;
    if (req.ContentLength is > 0) { var p = await req.ReadFromJsonAsync<ScanProgressDto>(); if (p is not null) { s.Progress = Math.Clamp(p.Progress, 0, 100); s.Stage = p.Stage; } }
    return Results.Ok();
});

app.Run();

sealed class Session
{
    public string Id { get; }
    public string Player { get; }
    public string AgentToken { get; }
    public DateTime ConnectedAtUtc { get; }
    public DateTime LastHeartbeatUtc { get; set; }
    public bool Started { get; set; }
    public bool Completed { get; set; }
    public int Progress { get; set; }
    public string Stage { get; set; } = "WAITING FOR STAFF";
    public string? CheckId { get; set; }
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public List<ScanItemDto> Results { get; } = new();
    public Session(string id, string player, string token, DateTime connected) { Id = id; Player = player; AgentToken = token; ConnectedAtUtc = connected; LastHeartbeatUtc = connected; }
    public PlayerStatusDto ToPlayerStatus() => new(Id, Player, DateTime.UtcNow - LastHeartbeatUtc < TimeSpan.FromSeconds(25), Started, Completed, ConnectedAtUtc, StartedAtUtc, CompletedAtUtc, Progress, Stage);
    public SessionStatusDto ToStatus() => new(Id, Player, DateTime.UtcNow - LastHeartbeatUtc < TimeSpan.FromSeconds(25), Started, Completed, CheckId, ConnectedAtUtc, StartedAtUtc, CompletedAtUtc, Progress, Stage, Results.ToList());
}

sealed class StaffAccount
{
    public string StaffId { get; }
    public string Name { get; }
    public string CodeHash { get; }
    public DateTime GrantedAtUtc { get; }
    public DateTime? ExpiresAtUtc { get; set; }
    public DateTime? LastLoginUtc { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public bool Revoked { get; set; }
    public int ActiveSessions { get; set; }
    public StaffAccount(string staffId, string name, string codeHash, DateTime grantedAtUtc, DateTime? expiresAtUtc) { StaffId = staffId; Name = name; CodeHash = codeHash; GrantedAtUtc = grantedAtUtc; ExpiresAtUtc = expiresAtUtc; }
}

sealed record StaffSession(string StaffId, string Name, bool IsAdmin, DateTime? ExpiresAtUtc, DateTime CreatedAtUtc)
{
    public bool Revoked { get; set; }
}
