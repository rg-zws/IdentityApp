using Microsoft.AspNetCore.Identity;

namespace IdentityApp.Models
{
    // Extends IdentityUser to add custom profile fields
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? ProfileBio { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public string FullName => $"{FirstName} {LastName}".Trim();
    }
}
