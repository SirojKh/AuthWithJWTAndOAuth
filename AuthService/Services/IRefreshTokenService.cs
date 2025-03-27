using Authentication_with_JWT_and_OAuth.ApplicationUser;

namespace Authentication_with_JWT_and_OAuth.AuthService.Services
{
    public interface IRefreshTokenService
    {
        Task<string> GenerateRefreshTokenAsync(ApplicationUser.ApplicationUser user);
        Task<bool> RevokeRefreshTokenAsync(string refreshToken);
        Task<ApplicationUser.ApplicationUser?> GetUserFromRefreshTokenAsync(string refreshToken);
    }
}