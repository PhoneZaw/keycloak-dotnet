using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CRBackend.Controllers
{
    [ApiController]
    [Route("/api/[controller]")]
    public class CRAmountController : ControllerBase
    {
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAmount()
        {
            try
            {
                var token = HttpContext.GetTokenAsync("access_token").Result;

                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                // jwtToken.Claims.FirstOrDefault(c => c.Type == "realm_access").Value;

                

                var userName = User.Claims.First(c => c.Type == "name").Value;
                var currentAmount = string.Join("", userName?.Select(System.Convert.ToInt32) ?? Array.Empty<int>());

                if (currentAmount.Length <= 0)
                {
                    currentAmount = "Zero";
                }

                return Ok(currentAmount);
                
            }
            catch (Exception e)
            {
                return StatusCode(403);
            }
        }
    }
}
