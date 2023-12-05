using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace CRBackend.Filters
{
    public class TokenFilter : IAsyncAuthorizationFilter
    {
        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {

            using var client = new HttpClient();

            var token = context.HttpContext.GetTokenAsync("access_token").Result;

            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

            var result = await client.GetAsync("http://192.168.2.21:8081/realms/myrealm/protocol/openid-connect/userinfo");

            if (!result.IsSuccessStatusCode)
            {
                context.Result = new UnauthorizedResult();

                return;
            }
        }
    }
}
