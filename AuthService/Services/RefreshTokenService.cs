using System.Security.Cryptography;
using System.Text;
using Authentication_with_JWT_and_OAuth.ApplicationUser;
using Authentication_with_JWT_and_OAuth.Data;
using Authentication_with_JWT_and_OAuth.Models;
using Microsoft.EntityFrameworkCore;

namespace Authentication_with_JWT_and_OAuth.AuthService.Services
{
    public class RefreshTokenService : IRefreshTokenService
    {
        private readonly AppDbContext _context;

        public RefreshTokenService(AppDbContext context)
        {
            _context = context;
        }

        public async Task<string> GenerateRefreshTokenAsync(ApplicationUser.ApplicationUser user)
        {
            // 1. Skapa ett unikt raw-token
            var rawToken = Convert.ToBase64String(Guid.NewGuid().ToByteArray());

            // 2. Hasha tokenet innan det sparas
            var hashedToken = HashToken(rawToken);

            var refreshToken = new RefreshToken
            {
                Token = hashedToken,
                Expires = DateTime.UtcNow.AddDays(7),
                UserId = user.Id
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            // 3. Returnera raw-token (inte det hashade)
            return rawToken;
        }

        public async Task<bool> RevokeRefreshTokenAsync(string token)
        {
            var hashed = HashToken(token);

            var storedToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == hashed && !t.IsRevoked);

            if (storedToken == null)
                return false;

            storedToken.IsRevoked = true;
            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<ApplicationUser.ApplicationUser?> GetUserFromRefreshTokenAsync(string token)
        {
            var hashed = HashToken(token);

            var storedToken = await _context.RefreshTokens
                .Include(t => t.User)
                .FirstOrDefaultAsync(t => t.Token == hashed && !t.IsRevoked && t.Expires > DateTime.UtcNow);

            return storedToken?.User;
        }

        private static string HashToken(string token)
        {
            var bytes = Encoding.UTF8.GetBytes(token);
            var hash = SHA256.HashData(bytes);
            return Convert.ToBase64String(hash);
        }
    }
}
