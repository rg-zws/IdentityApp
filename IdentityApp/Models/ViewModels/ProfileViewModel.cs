using System.ComponentModel.DataAnnotations;

namespace IdentityApp.Models.ViewModels
{
    public class ProfileViewModel
    {
        [Required]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Display(Name = "Bio")]
        public string? ProfileBio { get; set; }

        [Phone]
        [Display(Name = "Phone Number")]
        public string? PhoneNumber { get; set; }

        [Display(Name = "Department")]
        public string? Department { get; set; }

        [Display(Name = "Country")]
        public string? Country { get; set; }

        public string? Email { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
