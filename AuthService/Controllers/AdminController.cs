using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Authentication_with_JWT_and_OAuth.Data;
using Authentication_with_JWT_and_OAuth.Models;
using Microsoft.EntityFrameworkCore;

namespace Authentication_with_JWT_and_OAuth.AuthService.Controllers
{
    [ApiController]
    [Route("admin")]
    [Authorize(Roles = "ADMIN")]
    public class AdminController : ControllerBase
    {


        [HttpGet("ping")]
        public IActionResult Ping()
        {
            return Ok("✅ Admin-access bekräftad!");
        }

        [HttpGet("users")]
        [Authorize(Roles = "ADMIN")]
        public async Task<IActionResult> GetAllUsers([FromServices] UserManager<ApplicationUser.ApplicationUser> userManager)
        {
            var users = userManager.Users.ToList();

            var result = new List<object>();

            foreach (var user in users)
            {
                var roles = await userManager.GetRolesAsync(user);

                result.Add(new
                {
                    id = user.Id,
                    email = user.Email,
                    roles = roles
                });
            }

            return Ok(result);
        }


        [HttpDelete("users/{id}")]
        [Authorize(Roles = "ADMIN")]
        public async Task<IActionResult> DeleteUser(string id, [FromServices] UserManager<ApplicationUser.ApplicationUser> userManager)
        {
            var user = await userManager.FindByIdAsync(id);

            if (user == null)
                return NotFound("Användare hittades inte.");

            var result = await userManager.DeleteAsync(user);

            if (!result.Succeeded)
                return BadRequest("Det gick inte att ta bort användaren.");

            return Ok($"Användare med ID {id} togs bort.");
        }


        [HttpGet("logins/export")]
        [Authorize(Roles = "ADMIN")]
        public async Task<IActionResult> ExportLoginAuditsToCsv(
            [FromServices] AppDbContext context,
            [FromServices] UserManager<ApplicationUser.ApplicationUser> userManager,
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
                var user = await userManager.FindByEmailAsync(entry.Email);
                var userId = user?.Id ?? "Unknown";
                var roles = user != null ? string.Join(",", await userManager.GetRolesAsync(user)) : "Unknown";

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
                return Ok(enriched); // 👈 Visa JSON i Swagger

            // 📦 Skapa CSV
            var csv = new StringBuilder();
            csv.AppendLine("Id,Email,UserId,Roles,Timestamp,IpAddress,UserAgent");

            foreach (dynamic row in enriched)
            {
                var line = $"\"{row.Id}\",\"{row.Email}\",\"{row.UserId}\",\"{row.Roles}\",\"{row.Timestamp:yyyy-MM-dd HH:mm:ss}\",\"{row.IpAddress}\",\"{row.UserAgent}\"";
                csv.AppendLine(line);
            }

            var bytes = Encoding.UTF8.GetBytes(csv.ToString());
            var filename = $"login-audit-full-{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv";

            return File(bytes, "text/csv", filename);
        }







    }
}