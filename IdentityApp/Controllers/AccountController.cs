using IdentityApp.Models;
using IdentityApp.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        // GET /Account/Register
        [HttpGet]
        public IActionResult Register()
        {
            if (_signInManager.IsSignedIn(User))
                return RedirectToAction("Dashboard", "Home");

            return View();
        }

        // POST /Account/Register
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                ProfileBio = model.ProfileBio,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // Assign default "User" role
                await _userManager.AddToRoleAsync(user, "User");
                await _signInManager.SignInAsync(user, isPersistent: false);
                TempData["Success"] = $"Welcome, {user.FirstName}! Your account has been created.";
                return RedirectToAction("Dashboard", "Home");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        // GET /Account/Login
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            if (_signInManager.IsSignedIn(User))
                return RedirectToAction("Dashboard", "Home");

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        // POST /Account/Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!ModelState.IsValid)
                return View(model);

            var result = await _signInManager.PasswordSignInAsync(
                model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                TempData["Success"] = "You have successfully logged in.";
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    return Redirect(returnUrl);
                return RedirectToAction("Dashboard", "Home");
            }

            if (result.IsLockedOut)
            {
                ModelState.AddModelError(string.Empty, "Account locked out due to too many failed attempts. Try again later.");
                return View(model);
            }

            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return View(model);
        }

        // POST /Account/Logout
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            TempData["Success"] = "You have been logged out.";
            return RedirectToAction("Index", "Home");
        }

        // GET /Account/Profile
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Profile()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound();

            var model = new ProfileViewModel
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                ProfileBio = user.ProfileBio,
                PhoneNumber = user.PhoneNumber,
                Email = user.Email,
                CreatedAt = user.CreatedAt
            };
            return View(model);
        }

        // POST /Account/Profile
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public async Task<IActionResult> Profile(ProfileViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound();

            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.ProfileBio = model.ProfileBio;
            user.PhoneNumber = model.PhoneNumber;

            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                TempData["Success"] = "Profile updated successfully.";
                return RedirectToAction(nameof(Profile));
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        // -------------------------------------------------------
        // FORGOT PASSWORD
        // -------------------------------------------------------

        // GET /Account/ForgotPassword
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            if (_signInManager.IsSignedIn(User))
                return RedirectToAction("Dashboard", "Home");
            return View();
        }

        // POST /Account/ForgotPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);

            // Always show the same page whether user exists or not (security best practice)
            // This prevents user enumeration (attacker can't tell if email is registered)
            if (user == null)
                return RedirectToAction(nameof(ForgotPasswordConfirmation));

            // Generate a secure one-time token using Identity's built-in token provider
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Build the reset link
            var resetLink = Url.Action(
                action: nameof(ResetPassword),
                controller: "Account",
                values: new { token, email = user.Email },
                protocol: Request.Scheme)!;

            // In production → send this link via email (SendGrid, SMTP, etc.)
            // For learning → we pass it directly to the confirmation page
            TempData["ResetLink"] = resetLink;

            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }

        // GET /Account/ForgotPasswordConfirmation
        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        // -------------------------------------------------------
        // RESET PASSWORD  (arrived from the email link)
        // -------------------------------------------------------

        // GET /Account/ResetPassword?token=...&email=...
        [HttpGet]
        public IActionResult ResetPassword(string? token, string? email)
        {
            if (token == null || email == null)
                return BadRequest("Invalid password reset link.");

            var model = new ResetPasswordViewModel { Token = token, Email = email };
            return View(model);
        }

        // POST /Account/ResetPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return RedirectToAction(nameof(ResetPasswordConfirmation)); // same page (no enumeration)

            // Identity validates the token and sets the new password
            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);

            if (result.Succeeded)
                return RedirectToAction(nameof(ResetPasswordConfirmation));

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        // GET /Account/ResetPasswordConfirmation
        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        // -------------------------------------------------------
        // CHANGE PASSWORD  (requires login)
        // -------------------------------------------------------

        // GET /Account/ChangePassword
        [HttpGet]
        [Authorize]
        public IActionResult ChangePassword()
        {
            return View();
        }

        // POST /Account/ChangePassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound();

            // Identity checks current password before changing
            var result = await _userManager.ChangePasswordAsync(
                user, model.CurrentPassword, model.NewPassword);

            if (result.Succeeded)
            {
                // Refresh the login cookie so user stays signed in after password change
                await _signInManager.RefreshSignInAsync(user);
                TempData["Success"] = "Password changed successfully.";
                return RedirectToAction(nameof(Profile));
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        // GET /Account/AccessDenied
        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
