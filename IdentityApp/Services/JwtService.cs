using IdentityApp.Data;
using IdentityApp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace IdentityApp.Services
{
    public class JwtService
    {
        private readonly IConfiguration _config;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _db;

        public JwtService(
            IConfiguration config,
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext db)
        {
            _config = config;
            _userManager = userManager;
            _db = db;
        }

        // ── Generate Access Token (short-lived JWT) ───────────────────────────
        public async Task<string> GenerateAccessTokenAsync(ApplicationUser user)
        {
            var jwtSettings = _config.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"]!;
            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("firstName", user.FirstName),
                new Claim("lastName", user.LastName),
            };

            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            // Also pack custom claims (Department, Country) from AspNetUserClaims
            var userClaims = await _userManager.GetClaimsAsync(user);
            claims.AddRange(userClaims);

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

        // ── Generate Refresh Token (long-lived, stored in DB) ─────────────────
        // A Refresh Token is just a random string — NOT a JWT
        // It is stored in the database and used to get a new Access Token
        public async Task<RefreshToken> GenerateRefreshTokenAsync(ApplicationUser user)
        {
            // Generate a cryptographically secure random string
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            var tokenString = Convert.ToBase64String(randomBytes);

            var refreshToken = new RefreshToken
            {
                Token = tokenString,
                UserId = user.Id,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(7), // valid for 7 days
                IsUsed = false,
                IsRevoked = false
            };

            _db.RefreshTokens.Add(refreshToken);
            await _db.SaveChangesAsync();

            return refreshToken;
        }

        // ── Validate Refresh Token ────────────────────────────────────────────
        public async Task<RefreshToken?> ValidateRefreshTokenAsync(string token)
        {
            var refreshToken = _db.RefreshTokens
                .FirstOrDefault(r => r.Token == token);

            if (refreshToken == null) return null;       // not found
            if (!refreshToken.IsActive) return null;     // expired / used / revoked

            return refreshToken;
        }

        // ── Rotate Refresh Token ──────────────────────────────────────────────
        // Old token → marked as Used, new token → issued
        public async Task<(string AccessToken, RefreshToken NewRefreshToken)>
            RotateTokensAsync(RefreshToken oldToken, ApplicationUser user)
        {
            // Mark old token as used (one-time use)
            oldToken.IsUsed = true;
            _db.RefreshTokens.Update(oldToken);
            await _db.SaveChangesAsync();

            // Issue brand new tokens
            var newAccessToken = await GenerateAccessTokenAsync(user);
            var newRefreshToken = await GenerateRefreshTokenAsync(user);

            return (newAccessToken, newRefreshToken);
        }
    }
}
