using IdentityManagerServerApi.Data;
using IdentityManagerServerApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using SharedClassLibrary.Contracts;
using SharedClassLibrary.DTOs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace IdentityManagerServerApi.Repositories
{
    public class AccountRepository : IUserAccount
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration config;

        public AccountRepository(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.config = config;
        }


        public async Task<GeneralResponse> CreateAccount(UserDto userDto)
        {
            if (userDto == null) return new GeneralResponse(false, "User Model is empty.");

            var newUser = new ApplicationUser
            {
                Name = userDto.Name,
                Email = userDto.Email,
                PasswordHash = userDto.Password,
                UserName = userDto.Email
            };
            var user = await userManager.FindByEmailAsync(newUser.Email);
            if (user is not null)
            {
                return new GeneralResponse(false, "User is already registered.");
            }

            var createUser = await userManager.CreateAsync(newUser!, userDto.Password);
            if (!createUser.Succeeded)
            {
                return new GeneralResponse(false, "Error occured.. Please try again!!");
            }

            // Asign Default Role : Admin to first register; rest user
            var checkAdmin = await roleManager.FindByNameAsync("Admin");
            if (checkAdmin is null)
            {
                await roleManager.CreateAsync(new IdentityRole() { Name = "Admin" });
                await userManager.AddToRoleAsync(newUser, "Admin");
                return new GeneralResponse(true, "Account created as 'Admin'!");
            }
            else
            {
                var checkUser = await roleManager.FindByNameAsync("User");
                if (checkUser is null)
                {
                    await roleManager.CreateAsync(new IdentityRole() { Name = "User" });
                }

                await userManager.AddToRoleAsync(newUser, "User");
                return new GeneralResponse(true, "Account created as 'User'!");
            }
        }


        public async Task<LoginResponse> LoginAccount(LoginDto loginDto)
        {
            if (loginDto is null)
            {
                return new LoginResponse(false, null!, "Login container is empty.");
            }
            var getUser = await userManager.FindByEmailAsync(loginDto.Email);
            if (getUser is null)
            { return new LoginResponse(false, null!, "User not found!"); }

            bool checkUserPassword = await userManager.CheckPasswordAsync(getUser, loginDto.Password);
            if (!checkUserPassword)
            {
                return new LoginResponse(false, null!, "Incorrect Email/Password");
            }

            var getUserRole = await userManager.GetRolesAsync(getUser);
            var userSession = new UserSession(getUser.Id, getUser.Name, getUser.Email, getUserRole.First());

            string token = GenrateToken(userSession);
            return new LoginResponse(true, token, "Login Completed!!");
        }

        private string GenrateToken(UserSession userSession)
        {
            var jwtSection = config.GetSection(nameof(JwtSection)).Get<JwtSection>();

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection.Key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userSession.Id.ToString()),
                new Claim(ClaimTypes.Name, userSession.Name),
                new Claim(ClaimTypes.Email, userSession.Email),
                new Claim(ClaimTypes.Role, userSession.Role),
            };
            var token = new JwtSecurityToken(
                issuer: jwtSection.Issuer,
                audience: jwtSection.Audience,
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
