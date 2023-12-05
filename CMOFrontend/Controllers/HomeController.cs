using CMOFrontend.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using System.Net.Http;
using System.IdentityModel.Tokens.Jwt;

namespace CMOFrontend.Controllers
{
    public class HomeController : Controller
    {

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Token()
        {

            var token = HttpContext.GetTokenAsync("access_token").Result;

            if (token == null)
            {
                ViewData["Token"] = "Unauthorize";
                return View();
            }
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

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
                return StatusCode((int)result.StatusCode);

            var data = await result.Content.ReadAsStringAsync();

            Console.WriteLine("In Controller {0}", data);

            return View("CityRewards", data);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
