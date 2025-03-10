using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthWEBAPI.Entities;
using AuthWEBAPI.Model;
using AuthWEBAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthWEBAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase

    {
        private readonly IAuthService service;
        public AuthController(IAuthService service)
        {
            this.service = service;
        }
       

        [HttpPost("register")]
        public async Task<ActionResult<User?>> Register(UserDTO request) 
        {
            var user = await service.RegisterAsync(request);
            if (user == null) {
                return BadRequest("Already exists");
            }
 
            return Ok(user);

        }
        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDTO>> Login(UserDTO request)

        {
            var token= await service.LoginAsync(request);
            if (token==null)
                return BadRequest("Username/password not found");                   

            return Ok(token);
        }


        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDTO>> RefreshToken(RefreshTokenResponseDTO request)

        {
            var token = await service.RefreshTokenAsync(request);
            if (token == null)
                return BadRequest("Invalid Token not found");

            return Ok(token);
        }

        [HttpGet("auth-endpoint")]
        [Authorize]
        public ActionResult AuthCheck()
        {
            return Ok();
        }

        [HttpGet("admin-endpoint")]
        [Authorize(Roles ="Admin")]
        public ActionResult AdminCheck()
        {
            return Ok();
        }

    }
}
