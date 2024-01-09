using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CMOFrontend.Controllers
{
    public class AccountController : Controller
    {
        [Authorize]
        public IActionResult Login()
        {
            return Redirect("/");
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();

            var keycloakLogoutUrl = "http://192.168.2.21:6001/realms/myrealm/protocol/openid-connect/revoke";

            return Redirect("/");
        }

        public async Task<IActionResult> LogoutAll()
        {
            await HttpContext.SignOutAsync();

            var keycloakLogoutUrl = "http://192.168.2.21:6001/realms/myrealm/protocol/openid-connect/logout";
            return Redirect(keycloakLogoutUrl);
        }
    }
}
