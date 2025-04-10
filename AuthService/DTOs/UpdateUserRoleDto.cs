namespace Authentication_with_JWT_and_OAuth.AuthService.DTOs;

public class UpdateUserRoleDto
{
    public string Email { get; set; } = string.Empty;
    public string NewRole { get; set; } = string.Empty; // "USER" eller "ADMIN"
}
