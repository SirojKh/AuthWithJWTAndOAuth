using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Authentication_with_JWT_and_OAuth.ApplicationUser;
using Authentication_with_JWT_and_OAuth.AuthService.Services;
using Authentication_with_JWT_and_OAuth.AuthService.DTOs;

namespace Authentication_with_JWT_and_OAuth.AuthService.Controllers;

[ApiController]
[Route("auth/[controller]")]
public class ExternalAuthController : Controller
{
    private readonly UserManager<ApplicationUser.ApplicationUser> _userManager;
    private readonly ITokenService _tokenService;
    private readonly IRefreshTokenService _refreshTokenService;

    public ExternalAuthController(
        UserManager<ApplicationUser.ApplicationUser> userManager,
        ITokenService tokenService,
        IRefreshTokenService refreshTokenService)
    {
        _userManager = userManager;
        _tokenService = tokenService;
        _refreshTokenService = refreshTokenService;
    }

    [HttpGet("google-login")]
    public IActionResult GoogleLogin()
    {
        var props = new AuthenticationProperties
        {
            RedirectUri = Url.Action("GoogleCallback")
        };
        return Challenge(props, GoogleDefaults.AuthenticationScheme);
    }

    [HttpGet("googlecallback")]
    public async Task<IActionResult> GoogleCallback()
    {
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (!result.Succeeded || result.Principal == null)
            return Unauthorized("Google-autentisering misslyckades.");

        var email = result.Principal.FindFirst(ClaimTypes.Email)?.Value;

        if (string.IsNullOrEmpty(email))
            return Unauthorized("E-post kunde inte hämtas från Google");

        // Kontrollera om användaren redan finns
        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            return BadRequest("Användaren finns redan. Logga in med e-post och lösenord.");
        }

        return Ok(new
        {
            email,
            message = "✅ Google-verifiering lyckades. Fortsätt med att välja ett lösenord via /auth/externalauth/set-password."
        });
    }


    [HttpPost("set-password")]
    public async Task<IActionResult> SetPassword([FromBody] SetPasswordDto dto)
    {
        var existingUser = await _userManager.FindByEmailAsync(dto.Email);
        if (existingUser != null)
            return BadRequest("Användare finns redan.");

        var user = new ApplicationUser.ApplicationUser
        {
            Email = dto.Email,
            UserName = dto.Email
        };

        var result = await _userManager.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        await _userManager.AddToRoleAsync(user, "USER");

        return Ok("Användare skapad! Logga nu in med e-post och lösenord.");
    }
}
