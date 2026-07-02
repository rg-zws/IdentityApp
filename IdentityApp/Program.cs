using IdentityApp.Data;
using IdentityApp.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// EF Core + PostgreSQL
var connectionString = Environment.GetEnvironmentVariable("DATABASE_URL")
    ?? builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString));

// ASP.NET Core Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Cookie settings (for MVC web pages)
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
});

// JWT settings
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"]!;

builder.Services.AddAuthentication()
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,           // checks expiry
            ValidateIssuerSigningKey = true,   // checks signature
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
            ClockSkew = TimeSpan.Zero          // no grace period on expiry
        };

        // Return proper JSON instead of empty body for 401 and 403
        options.Events = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents
        {
            OnChallenge = context =>
            {
                // 401 Unauthorized — no token or invalid token
                context.HandleResponse();
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync(
                    """{"status": 401, "message": "Unauthorized. Please login and provide a valid token."}""");
            },
            OnForbidden = context =>
            {
                // 403 Forbidden — valid token but wrong role
                context.Response.StatusCode = 403;
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync(
                    """{"status": 403, "message": "Access denied. You do not have the required role (Admin)."}""");
            }
        };
    });

builder.Services.AddScoped<IdentityApp.Services.JwtService>();

// ── POLICY-BASED AUTHORIZATION ───────────────────────────────────────────────
// Policies are named rules. Much more powerful than just [Authorize(Roles=...)]
builder.Services.AddAuthorization(options =>
{
    // Policy 1: Simple role check (same as [Authorize(Roles="Admin")])
    options.AddPolicy("AdminOnly",
        policy => policy.RequireRole("Admin"));

    // Policy 2: Claim check — user must have Department = Engineering
    options.AddPolicy("EngineeringOnly",
        policy => policy.RequireClaim("Department", "Engineering"));

    // Policy 3: Claim check — user must be from India
    options.AddPolicy("IndiaOnly",
        policy => policy.RequireClaim("Country", "India"));

    // Policy 4: Multiple rules — must be Admin AND from India
    options.AddPolicy("IndianAdmin", policy =>
    {
        policy.RequireRole("Admin");
        policy.RequireClaim("Country", "India");
    });

    // Policy 5: Custom logic using RequireAssertion — any C# expression
    options.AddPolicy("EngineeringOrAdmin", policy =>
        policy.RequireAssertion(context =>
            context.User.IsInRole("Admin") ||
            context.User.HasClaim("Department", "Engineering")));
});
// ─────────────────────────────────────────────────────────────────────────────

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Seed default roles and admin user
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

    string[] roles = ["Admin", "User"];
    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));
    }

    // Create a default admin account for demonstration
    const string adminEmail = "admin@identityapp.com";
    if (await userManager.FindByEmailAsync(adminEmail) == null)
    {
        var admin = new ApplicationUser
        {
            UserName = adminEmail,
            Email = adminEmail,
            FirstName = "Admin",
            LastName = "User",
            ProfileBio = "I am the site administrator.",
            CreatedAt = DateTime.UtcNow,
            EmailConfirmed = true,
            LockoutEnabled = true
        };
        var result = await userManager.CreateAsync(admin, "Admin@123");
        if (result.Succeeded)
            await userManager.AddToRoleAsync(admin, "Admin");
    }
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
