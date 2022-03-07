using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using LiteForum.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace LiteForum.Controllers
{
   [ApiController]
   [Route("[controller]")]
   public class AuthController : ControllerBase
   {
      private readonly IConfiguration _configuration;
      public static User user = new();

      public AuthController(IConfiguration configuration)
      {
         _configuration = configuration;
      }

      [HttpPost("register")]
      public async Task<ActionResult<User>> Register(UserDto request)
      {
         CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

         user.Username = request.Username;
         user.PasswordHash = passwordHash;
         user.PasswordSalt = passwordSalt;

         return Ok(user);
      }

      [HttpPost("login")]
      public async Task<ActionResult<string>> Login(UserDto request)
      {
         if (!user.Username.Equals(request.Username))
         {
            return BadRequest("User not found.");
         }

         if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
         {
            return BadRequest("Wrong password.");
         }

         var token = CreateToken(user);
         return Ok(token);
      }

      private string CreateToken(User user)
      {
         var claims = new List<Claim>
         {
            new(ClaimTypes.Name, user.Username)
         };

         var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
            _configuration.GetSection("AppSettings:Token").Value));

         var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

         var token = new JwtSecurityToken(
            claims: claims, 
            expires: DateTime.Now.AddDays(1),
            signingCredentials: creds);

         return new JwtSecurityTokenHandler().WriteToken(token);
      }

      private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
      {
         using (var hmac = new HMACSHA512())
         {
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
         }
      }

      private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
      {
         using (var hmac = new HMACSHA512(passwordSalt))
         {
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(passwordHash);
         }
      }
   }
}
