using System.Diagnostics;
using IdentityApp.Models;
using IdentityApp.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public HomeController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        // Requires login
        [Authorize]
        public async Task<IActionResult> Dashboard()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound();

            var roles = await _userManager.GetRolesAsync(user);
            ViewData["UserRoles"] = roles;
            ViewData["UserName"] = user.FullName.Length > 0 ? user.FullName : user.Email;
            ViewData["MemberSince"] = user.CreatedAt.ToString("MMMM dd, yyyy");
            return View();
        }

        // Requires Admin role
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Admin()
        {
            var users = _userManager.Users.ToList();
            var userRoleList = new List<(ApplicationUser User, IList<string> Roles)>();

            foreach (var u in users)
            {
                var roles = await _userManager.GetRolesAsync(u);
                userRoleList.Add((u, roles));
            }

            ViewData["UserRoleList"] = userRoleList;
            return View();
        }

        public IActionResult JwtDemo() => View();

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
