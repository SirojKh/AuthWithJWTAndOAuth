namespace Authentication_with_JWT_and_OAuth.AuthService.DTOs;

public class RegisterDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool IsAdmin { get; set; } = false; // enkel rollhantering

}