using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApp.Models;
using System.Security.Claims;

namespace IdentityApp.Controllers
{
    // [Authorize] on the whole controller = every action needs login
    [Authorize]
    public class DemoController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public DemoController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        // ── ❸ AllowAnonymous ─────────────────────────────────────────────────
        // Controller says [Authorize] but this action says [AllowAnonymous]
        // Result: anyone can visit this, even without logging in
        [AllowAnonymous]
        public IActionResult PublicPage()
        {
            ViewData["Message"] =
                "This page is PUBLIC even though the controller has [Authorize]. " +
                "[AllowAnonymous] always wins.";
            return View("DemoPage");
        }

        // ── ❶ Claims demo ────────────────────────────────────────────────────
        // Requires login (from controller-level [Authorize])
        public IActionResult MyClaims()
        {
            // Read ALL claims from the current user's cookie
            var claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();
            ViewData["Claims"] = claims;
            ViewData["Message"] = "All claims stored in your login cookie:";
            return View("DemoPage");
        }

        // ── ❷ Policy: EngineeringOnly ────────────────────────────────────────
        // Only users whose Department claim = "Engineering" can enter
        [Authorize(Policy = "EngineeringOnly")]
        public IActionResult EngineeringPage()
        {
            ViewData["Message"] =
                "You passed the [EngineeringOnly] policy! " +
                "Your Department claim = 'Engineering'.";
            return View("DemoPage");
        }

        // ── ❷ Policy: IndiaOnly ──────────────────────────────────────────────
        // Only users whose Country claim = "India" can enter
        [Authorize(Policy = "IndiaOnly")]
        public IActionResult IndiaPage()
        {
            ViewData["Message"] =
                "You passed the [IndiaOnly] policy! " +
                "Your Country claim = 'India'.";
            return View("DemoPage");
        }

        // ── ❷ Policy: AdminOnly ──────────────────────────────────────────────
        [Authorize(Policy = "AdminOnly")]
        public IActionResult AdminOnlyPage()
        {
            ViewData["Message"] =
                "You passed the [AdminOnly] policy! You have the Admin role.";
            return View("DemoPage");
        }

        // ── ❷ Policy: EngineeringOrAdmin (custom assertion) ──────────────────
        [Authorize(Policy = "EngineeringOrAdmin")]
        public IActionResult EngineeringOrAdminPage()
        {
            ViewData["Message"] =
                "You passed [EngineeringOrAdmin] policy — you are either " +
                "an Admin OR in Engineering department.";
            return View("DemoPage");
        }

        // ── ❹ Security Stamp demo ────────────────────────────────────────────
        // This action MANUALLY changes the SecurityStamp
        // Simulates what happens when admin bans a user / role changes
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> ResetSecurityStamp(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();

            var oldStamp = user.SecurityStamp;

            // UpdateSecurityStampAsync generates a new random GUID for SecurityStamp
            // This will force ALL sessions for this user to log out
            // (within the validation interval — default 30 mins)
            await _userManager.UpdateSecurityStampAsync(user);

            var newStamp = (await _userManager.FindByIdAsync(userId))!.SecurityStamp;

            TempData["Success"] =
                $"SecurityStamp changed! " +
                $"Old: {oldStamp?[..8]}... → New: {newStamp?[..8]}... " +
                $"All sessions for this user will be invalidated.";

            return RedirectToAction("SecurityStampDemo");
        }

        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> SecurityStampDemo()
        {
            var users = _userManager.Users.ToList();
            ViewData["Users"] = users;
            ViewData["Message"] = "Security Stamp Demo — Admin can reset any user's stamp:";
            return View("DemoPage");
        }
    }
}
