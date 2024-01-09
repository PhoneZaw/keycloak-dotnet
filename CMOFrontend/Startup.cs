using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using CMOFrontend.Helper;
using CMOFrontend.Models;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace CMOFrontend
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(options =>
            {
                //options.Authority = "http://192.168.2.21:8081/realms/myrealm";
                options.Authority = "http://dev.keycloak.com/realms/myrealm";
                //options.Authority = "http://192.168.2.21:6001/realms/myrealm";
                options.RequireHttpsMetadata = false;
                options.ClientId = "cmo_client";
                options.ClientSecret = "jqZT0VC6cfSfCQ5rIZrWc85nCTnkarHA";
                options.ResponseType = "code";
                options.SaveTokens = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                //options.Scope.Add("roles");
                //options.Scope.Add("age");
                options.CallbackPath = "/signin-oidc"; // Set the callback path
                options.SignedOutCallbackPath = "/signout-callback-oidc";
                options.SaveTokens = true;

                options.Events = new OpenIdConnectEvents()
                {

                    OnTokenValidated = context =>
                    {
                        var accessToken = context.SecurityToken as JwtSecurityToken;
                        if (accessToken != null)
                        {
                            // Extract claims from the access token and add them to ClaimsPrincipal
                            var idToken = context.TokenEndpointResponse?.IdToken;
                            var claims = accessToken.Claims.ToList();
                            if (claims.FirstOrDefault(c => c.Type == "realm_access") is not null)
                            {
                                var roleClaims = JsonHelper.Deserialize<RealmAccess>(claims.FirstOrDefault(c => c.Type == "realm_access")?.Value);

                                foreach (var role in roleClaims.Roles)
                                {
                                    claims.Add(new Claim(ClaimTypes.Role, role));
                                }
                            }

                            context.Principal.AddIdentity(new ClaimsIdentity(claims));
                        }

                        return Task.CompletedTask;

                    },

                };
            });

            services.Configure<CookiePolicyOptions>(options =>
            {
                options.Secure = CookieSecurePolicy.Always;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseCookiePolicy(new CookiePolicyOptions()
            {
                MinimumSameSitePolicy = SameSiteMode.Lax
            });

            //app.Use(async (context, next) =>
            //{
            //    if (context.User.Identity is { IsAuthenticated: true } && !context.User.IsInRole("Employee"))
            //    {
            //        context.Response.StatusCode = 403;

            //        await context.Response.WriteAsync("Forbidden");

            //        return;
            //    }

            //    await next();
            //});

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
