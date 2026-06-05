namespace IdentityApp.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }

        // The random token string stored in DB
        public string Token { get; set; } = string.Empty;

        // Which user this belongs to
        public string UserId { get; set; } = string.Empty;
        public ApplicationUser User { get; set; } = null!;

        public DateTime ExpiresAt { get; set; }   // 7 days from creation
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public bool IsUsed { get; set; } = false;   // true after it's been exchanged
        public bool IsRevoked { get; set; } = false; // true if manually invalidated

        // Computed: is this token still valid?
        public bool IsActive => !IsUsed && !IsRevoked && DateTime.UtcNow < ExpiresAt;
    }
}
