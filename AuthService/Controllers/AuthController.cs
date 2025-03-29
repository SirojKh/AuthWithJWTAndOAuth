using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Authentication_with_JWT_and_OAuth.AuthService.DTOs;
using Authentication_with_JWT_and_OAuth.AuthService.Services;
using Authentication_with_JWT_and_OAuth.Data;
using Authentication_with_JWT_and_OAuth.Dtos;
using Authentication_with_JWT_and_OAuth.Models;
using Microsoft.AspNetCore.Authorization;

namespace Authentication_with_JWT_and_OAuth.AuthService.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser.ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser.ApplicationUser> _signInManager;
    private readonly ITokenService _tokenService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly AppDbContext _context;



    public AuthController(
        UserManager<ApplicationUser.ApplicationUser> userManager,
        SignInManager<ApplicationUser.ApplicationUser> signInManager,
        ITokenService tokenService,
        IRefreshTokenService refreshTokenService,
        AppDbContext context)

    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _refreshTokenService = refreshTokenService;
        _context = context;

    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        var userExists = await _userManager.FindByEmailAsync(dto.Email);
        if (userExists != null)
            return BadRequest("Användare med denna e-postadress finns redan.");

        var user = new ApplicationUser.ApplicationUser
        {
            Email = dto.Email,
            UserName = dto.Email
        };

        var result = await _userManager.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        var isAuthenticated = HttpContext.User.Identity?.IsAuthenticated == true;
        var isCallerAdmin = HttpContext.User.IsInRole("ADMIN");

        // Tilldela ADMIN endast om:
        // - Den som registrerar är inloggad
        // - Den är en admin
        // - Och den begär isAdmin: true
        if (isAuthenticated && isCallerAdmin && dto.IsAdmin)
        {
            await _userManager.AddToRoleAsync(user, "ADMIN");
        }
        else
        {
            await _userManager.AddToRoleAsync(user, "USER");
        }

        return Ok("Användare skapad!");
    }






    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null)
            return Unauthorized("Felaktig e-post eller lösenord.");

        var result = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, false);
        if (!result.Succeeded)
            return Unauthorized("Felaktig e-post eller lösenord.");

        var roles = await _userManager.GetRolesAsync(user);
        var accessToken = await _tokenService.CreateTokenAsync(user, roles);
        var refreshToken = await _refreshTokenService.GenerateRefreshTokenAsync(user);

        // 🕵️‍♂️ AUDIT TRAIL
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        var userAgent = Request.Headers["User-Agent"].ToString();

        var audit = new LoginAudit
        {
            Email = user.Email,
            Timestamp = DateTime.UtcNow,
            IpAddress = ip,
            UserAgent = userAgent
        };

        _context.LoginAudits.Add(audit);
        await _context.SaveChangesAsync();

        // 🍪 Set refresh-token cookie
        Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddDays(7)
        });

        return Ok(new
        {
            accessToken = accessToken
        });
    }




    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        var tokenFromCookie = Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(tokenFromCookie))
            return Unauthorized("Ingen refresh-token hittades.");

        var user = await _refreshTokenService.GetUserFromRefreshTokenAsync(tokenFromCookie);
        if (user == null)
            return Unauthorized("Ogiltigt eller utgånget refresh-token.");

        var roles = await _userManager.GetRolesAsync(user);
        var newAccessToken = await _tokenService.CreateTokenAsync(user, roles);
        var newRefreshToken = await _refreshTokenService.GenerateRefreshTokenAsync(user);

        // Skriv över cookien med nytt refresh-token
        Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddDays(7)
        });

        return Ok(new
        {
            accessToken = newAccessToken
        });
    }



    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] RefreshRequestDto request)
    {
        var result = await _refreshTokenService.RevokeRefreshTokenAsync(request.RefreshToken);

        if (!result)
            return BadRequest("Ogiltigt eller redan använt refresh-token.");

        return Ok("Utloggning lyckades. Refresh-token ogiltigförklarad.");
    }


}