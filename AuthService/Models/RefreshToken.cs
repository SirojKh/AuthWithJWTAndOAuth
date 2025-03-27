using System.ComponentModel.DataAnnotations;

namespace Authentication_with_JWT_and_OAuth.Models
{
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }
        public string Token { get; set; } = string.Empty;
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; } = false;

        public string UserId { get; set; } = string.Empty;
        public ApplicationUser.ApplicationUser? User { get; set; }
    }
}