using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CRFrontend.Controllers
{
    public class AccountController : Controller
    {
        [Authorize]
        public IActionResult Login()
        {
            return Redirect("/");
        }

        public IActionResult Logout()
        {
            HttpContext.SignOutAsync();

            return Redirect("/");
        }

        public IActionResult LogoutAll()
        {
            HttpContext.SignOutAsync();

            var keycloakLogoutUrl = "http://192.168.2.21:8081/realms/myrealm/protocol/openid-connect/logout";
            return Redirect(keycloakLogoutUrl);
        }
    }
}
