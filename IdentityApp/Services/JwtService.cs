using IdentityApp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace IdentityApp.Services
{
    public class JwtService
    {
        private readonly IConfiguration _config;
        private readonly UserManager<ApplicationUser> _userManager;

        public JwtService(IConfiguration config, UserManager<ApplicationUser> userManager)
        {
            _config = config;
            _userManager = userManager;
        }

        public async Task<string> GenerateTokenAsync(ApplicationUser user)
        {
            var jwtSettings = _config.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"]!;
            var roles = await _userManager.GetRolesAsync(user);

            // Claims = data packed inside the token
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),           // subject (user id)
                new Claim(JwtRegisteredClaimNames.Email, user.Email!),     // email
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // unique token id
                new Claim("firstName", user.FirstName),
                new Claim("lastName", user.LastName),
            };

            // Add role claims
            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiry = DateTime.UtcNow.AddMinutes(
                double.Parse(jwtSettings["ExpiryMinutes"]!));

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: expiry,
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
