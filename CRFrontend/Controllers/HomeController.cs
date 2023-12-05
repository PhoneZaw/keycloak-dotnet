using CRFrontend.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace CRFrontend.Controllers
{
    public class HomeController : Controller
    {

        public IActionResult Index()
        {
            return View();
        }
        
        [Authorize]
        public async Task<IActionResult> CityRewards()
        {

            using var client = new HttpClient();

            var token = HttpContext.GetTokenAsync("access_token").Result;

            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

            var result = await client.GetAsync("https://localhost:44309/api/CRAmount");

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
