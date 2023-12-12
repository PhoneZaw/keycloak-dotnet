using CRFrontend.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using CRBackend.Helper;

namespace CRFrontend.Controllers
{
    public class HomeController : Controller
    {

        public IActionResult Index()
        {
            var token = HttpContext.GetTokenAsync("access_token").Result;

            ViewData["Token"] = "Unauthorize";

            ViewData["roles"] = "";

            if (token == null)
            {
                return View();
            }

            var handler = new JwtSecurityTokenHandler();
            var accessToken = handler.ReadJwtToken(token);

            var claims = accessToken.Claims.ToList();

            var realmClaim = claims.FirstOrDefault(c => c.Type == "realm_access")?.Value;

            var userName = User.Claims.FirstOrDefault(c => c.Type == "name")?.Value;

            if (User.HasClaim(c => c.Type == "age"))
            {
                ViewData["age"] = $"Age : {claims.FirstOrDefault(c => c.Type == "age")?.Value}";
            }
            else
            {
                ViewData["age"] = "Age is not allowed";
            }

            if (realmClaim != null)
            {
                var realmAccessClaim = JsonHelper.Deserialize<RealmAccess>(realmClaim);

                var roles = realmAccessClaim.Roles.Where(c => c is "Employee" or "Customer").ToList();

                if (!roles.Contains("Employee"))
                {
                    ViewData["Error"] = "Forbidden";
                }

                ViewData["roles"] = string.Join(", ", roles);
            }

            ViewData["Token"] = token;

            return View();
        }
        
        [Authorize]
        public async Task<IActionResult> CityRewards()
        {

            using var client = new HttpClient();

            var token = HttpContext.GetTokenAsync("access_token").Result;

            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

            var result = await client.GetAsync("https://localhost:44309/api/CRAmount");

            if (!result.IsSuccessStatusCode)
            {
                ViewData["Error"] = "Unauthorize";
                return View();
            }

            var data = await result.Content.ReadAsStringAsync();

            Console.WriteLine("In Controller {0}", data);

            return View("CityRewards", data);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
