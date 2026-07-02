using IdentityApp.Data;
using IdentityApp.Models;
using IdentityApp.Models.ViewModels;
using IdentityApp.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthApiController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JwtService _jwtService;
        private readonly ApplicationDbContext _db;

        public AuthApiController(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            JwtService jwtService,
            ApplicationDbContext db)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtService = jwtService;
            _db = db;
        }

        // ── POST /api/authapi/login ───────────────────────────────────────────
        // Returns BOTH access token (short) + refresh token (long)
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return Unauthorized(new { message = "Invalid email or password." });

            var result = await _signInManager.CheckPasswordSignInAsync(
                user, model.Password, lockoutOnFailure: true);

            if (result.IsLockedOut)
                return Unauthorized(new { message = "Account locked. Try again later." });

            if (!result.Succeeded)
                return Unauthorized(new { message = "Invalid email or password." });

            var roles = await _userManager.GetRolesAsync(user);

            // Generate BOTH tokens
            var accessToken = await _jwtService.GenerateAccessTokenAsync(user);
            var refreshToken = await _jwtService.GenerateRefreshTokenAsync(user);

            return Ok(new
            {
                // Short-lived JWT — use this for every API call
                accessToken,
                accessTokenExpiry = DateTime.UtcNow.AddMinutes(10),

                // Long-lived random string — store this safely
                // Send it to /api/authapi/refresh when access token expires
                refreshToken = refreshToken.Token,
                refreshTokenExpiry = refreshToken.ExpiresAt,

                user = new { user.Id, user.Email, user.FirstName, user.LastName, roles }
            });
        }

        // ── POST /api/authapi/refresh ─────────────────────────────────────────
        // Client sends expired accessToken + valid refreshToken
        // Server returns a NEW accessToken + NEW refreshToken (rotation)
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequestModel model)
        {
            if (string.IsNullOrEmpty(model.RefreshToken))
                return BadRequest(new { message = "Refresh token is required." });

            // Validate the refresh token from DB
            var storedToken = await _jwtService.ValidateRefreshTokenAsync(model.RefreshToken);
            if (storedToken == null)
                return Unauthorized(new { message = "Invalid or expired refresh token. Please login again." });

            // Load the user
            var user = await _userManager.FindByIdAsync(storedToken.UserId);
            if (user == null)
                return Unauthorized(new { message = "User not found." });

            // Rotate: mark old token as used, issue new pair
            var (newAccessToken, newRefreshToken) =
                await _jwtService.RotateTokensAsync(storedToken, user);

            return Ok(new
            {
                accessToken = newAccessToken,
                accessTokenExpiry = DateTime.UtcNow.AddMinutes(10),
                refreshToken = newRefreshToken.Token,
                refreshTokenExpiry = newRefreshToken.ExpiresAt,
                message = "Tokens refreshed successfully."
            });
        }

        // ── POST /api/authapi/revoke ──────────────────────────────────────────
        // Logout from API — marks refresh token as revoked in DB
        [HttpPost("revoke")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> Revoke([FromBody] RefreshRequestModel model)
        {
            var storedToken = _db.RefreshTokens
                .FirstOrDefault(r => r.Token == model.RefreshToken);

            if (storedToken == null)
                return BadRequest(new { message = "Token not found." });

            storedToken.IsRevoked = true;
            _db.RefreshTokens.Update(storedToken);
            await _db.SaveChangesAsync();

            return Ok(new { message = "Logged out. Refresh token revoked." });
        }

        // ── GET /api/authapi/profile ──────────────────────────────────────────
        [HttpGet("profile")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> Profile()
        {
            var userId = _userManager.GetUserId(User);
            var user = await _userManager.FindByIdAsync(userId!);
            if (user == null) return NotFound();

            var roles = await _userManager.GetRolesAsync(user);
            var claims = await _userManager.GetClaimsAsync(user);

            return Ok(new
            {
                user.Id, user.Email, user.FirstName, user.LastName,
                user.ProfileBio, user.Department, user.Country,
                user.CreatedAt, roles,
                customClaims = claims.Select(c => new { c.Type, c.Value })
            });
        }

        // ── GET /api/authapi/admin-only ───────────────────────────────────────
        [HttpGet("admin-only")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme,
                   Roles = "Admin")]
        public IActionResult AdminOnly()
        {
            return Ok(new
            {
                message = "You are an Admin! JWT role check passed.",
                accessedAt = DateTime.UtcNow
            });
        }
    }

    // Request model for refresh and revoke endpoints
    public class RefreshRequestModel
    {
        public string RefreshToken { get; set; } = string.Empty;
    }
}
