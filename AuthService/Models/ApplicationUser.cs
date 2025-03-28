namespace Authentication_with_JWT_and_OAuth.ApplicationUser;

using Microsoft.AspNetCore.Identity;

public class ApplicationUser : IdentityUser
{
    public string? Role { get; set; } // enkel rollhantering
}
