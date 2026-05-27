using IdentityApp.Models;
using IdentityApp.Models.ViewModels;
using IdentityApp.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    // This is a REST API controller — returns JSON, not Views
    [Route("api/[controller]")]
    [ApiController]
    public class AuthApiController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JwtService _jwtService;

        public AuthApiController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            JwtService jwtService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtService = jwtService;
        }

        // POST /api/authapi/login
        // Body: { "email": "...", "password": "..." }
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

            // Generate JWT token
            var token = await _jwtService.GenerateTokenAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                token,                              // the JWT string
                expiry = DateTime.UtcNow.AddMinutes(60),
                user = new
                {
                    user.Id,
                    user.Email,
                    user.FirstName,
                    user.LastName,
                    roles
                }
            });
        }

        // GET /api/authapi/profile
        // Header: Authorization: Bearer <token>
        [HttpGet("profile")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> Profile()
        {
            // UserManager.GetUserId() reads ClaimTypes.NameIdentifier
            // which is what JWT middleware maps "sub" to automatically
            var userId = _userManager.GetUserId(User);

            var user = await _userManager.FindByIdAsync(userId!);
            if (user == null) return NotFound();

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                user.Id,
                user.Email, 
                user.FirstName,
                user.LastName,
                user.ProfileBio,
                user.CreatedAt,
                roles
            });
        }

        // GET /api/authapi/admin-only
        // Only users with Admin role can access this
        [HttpGet("admin-only")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
        public IActionResult AdminOnly()
        {
            return Ok(new
            {
                message = "You are an Admin! JWT role check passed.",
                accessedAt = DateTime.UtcNow
            });
        }
    }
}
