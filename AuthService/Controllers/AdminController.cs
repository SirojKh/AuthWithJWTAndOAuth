using System.Text;
using Authentication_with_JWT_and_OAuth.AuthService.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Authentication_with_JWT_and_OAuth.Data;
using Microsoft.EntityFrameworkCore;

namespace Authentication_with_JWT_and_OAuth.AuthService.Controllers;

[ApiController]
[Route("admin")]
[Authorize(Roles = "ADMIN")]
public class AdminController : ControllerBase
{
    private readonly UserManager<ApplicationUser.ApplicationUser> _userManager;

    public AdminController(UserManager<ApplicationUser.ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    [HttpGet("ping")]
    public IActionResult Ping()
    {
        return Ok("✅ Admin-access bekräftad!");
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetUsers(
        [FromQuery] string? email,
        [FromQuery] string? role)
    {
        var users = _userManager.Users.ToList();
        var result = new List<object>();

        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);

            if (!string.IsNullOrEmpty(role) && !roles.Contains(role.ToUpper()))
                continue;

            if (!string.IsNullOrEmpty(email) && !user.Email!.ToLower().Contains(email.ToLower()))
                continue;

            result.Add(new
            {
                id = user.Id,
                email = user.Email,
                roles
            });
        }

        return Ok(result);
    }

    [HttpGet("logins/export")]
    public async Task<IActionResult> ExportLoginAuditsToCsv(
        [FromServices] AppDbContext context,
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] string? email,
        [FromQuery] bool download = false)
    {
        var query = context.LoginAudits.AsQueryable();

        if (from.HasValue)
            query = query.Where(x => x.Timestamp >= from.Value);

        if (to.HasValue)
            query = query.Where(x => x.Timestamp <= to.Value);

        if (!string.IsNullOrEmpty(email))
            query = query.Where(x => x.Email.ToLower().Contains(email.ToLower()));

        var audits = await query
            .OrderByDescending(x => x.Timestamp)
            .ToListAsync();

        var enriched = new List<object>();

        foreach (var entry in audits)
        {
            var user = await _userManager.FindByEmailAsync(entry.Email);
            var userId = user?.Id ?? "Unknown";
            var roles = user != null ? string.Join(",", await _userManager.GetRolesAsync(user)) : "Unknown";

            enriched.Add(new
            {
                entry.Id,
                entry.Email,
                UserId = userId,
                Roles = roles,
                entry.Timestamp,
                entry.IpAddress,
                entry.UserAgent
            });
        }

        if (!download)
            return Ok(enriched); // Visa JSON i Swagger

        // Skapa CSV
        var csv = new StringBuilder();
        csv.AppendLine("Id,Email,UserId,Roles,Timestamp,IpAddress,UserAgent");

        foreach (dynamic row in enriched)
        {
            var line = $"\"{row.Id}\",\"{row.Email}\",\"{row.UserId}\",\"{row.Roles}\",\"{row.Timestamp:yyyy-MM-dd HH:mm:ss}\",\"{row.IpAddress}\",\"{row.UserAgent}\"";
            csv.AppendLine(line);
        }

        var bytes = Encoding.UTF8.GetBytes(csv.ToString());
        var filename = $"login-audit-{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv";

        return File(bytes, "text/csv", filename);
    }

    [HttpPost("update-role")]
    public async Task<IActionResult> UpdateUserRole([FromBody] UpdateUserRoleDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null)
            return NotFound("Användaren finns inte.");

        var currentRoles = await _userManager.GetRolesAsync(user);
        var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);

        if (!removeResult.Succeeded)
            return BadRequest("Kunde inte ta bort nuvarande roller.");

        var addResult = await _userManager.AddToRoleAsync(user, dto.NewRole.ToUpper());
        if (!addResult.Succeeded)
            return BadRequest("Kunde inte lägga till ny roll.");

        return Ok($"Rollen för {dto.Email} har ändrats till {dto.NewRole.ToUpper()}");
    }
}
