using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SharedClassLibrary.Contracts;
using SharedClassLibrary.DTOs;

namespace IdentityManagerServerApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly IUserAccount userAccount;

        public AccountController(IUserAccount userAccount)
        {
            this.userAccount=userAccount;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserDto userDto)
        {
            var response = await userAccount.CreateAccount(userDto);
            return Ok(response);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            var response = await userAccount.LoginAccount(loginDto);
            return Ok(response);
        }

        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public ActionResult GetAdmin()
        {
            return Ok("Your admin is here!");
        }

        [HttpGet("user")]
        [Authorize(Roles = "User")]
        public ActionResult GetUser()
        {
            return Ok("Your user is here!");
        }
    }
}
