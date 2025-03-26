namespace Authentication_with_JWT_and_OAuth.AuthService.Services;

public interface ITokenService
{
    string CreateToken(ApplicationUser.ApplicationUser user, IList<string> roles);
}