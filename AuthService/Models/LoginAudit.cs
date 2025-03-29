namespace Authentication_with_JWT_and_OAuth.Models
{
    public class LoginAudit
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string IpAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
    }
}