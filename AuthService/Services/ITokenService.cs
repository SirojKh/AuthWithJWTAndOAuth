using Authentication_with_JWT_and_OAuth.ApplicationUser;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Authentication_with_JWT_and_OAuth.AuthService.Services
{
    public interface ITokenService
    {
        Task<string> CreateTokenAsync(ApplicationUser.ApplicationUser user, IList<string> roles);
    }
}