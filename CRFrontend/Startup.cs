using Microsoft.AspNetCore.Authentication.Cookies;
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

namespace CRFrontend
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
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
                options.Authority = "http://192.168.2.21:8081/realms/myrealm";
                options.RequireHttpsMetadata = false;
                options.ClientId = "cr_client";
                options.ClientSecret = "wqQmbaY2p23xtUb3GYmT2ESKqhTJGy6d";
                options.ResponseType = "code";
                options.SaveTokens = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.CallbackPath = "/signin-oidc"; // Set the callback path
                options.SignedOutCallbackPath = "/signout-callback-oidc";
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "pz",
                    RoleClaimType = "user"
                };

                options.Events = new OpenIdConnectEvents()
                {
                    OnAuthorizationCodeReceived = context =>
                    {
                        return Task.CompletedTask;
                    },

                    OnMessageReceived = context =>
                    {
                        return Task.CompletedTask;

                    },

                    OnRedirectToIdentityProvider = context =>
                    {
                        return Task.CompletedTask;

                    },

                    OnRedirectToIdentityProviderForSignOut = context =>
                    {
                        return Task.CompletedTask;
                    },

                    OnSignedOutCallbackRedirect = context =>
                    {
                        return Task.CompletedTask;

                    },

                    OnTokenResponseReceived = context =>
                    {

                        return Task.CompletedTask;

                    },

                    OnTokenValidated = context =>
                    {
                        return Task.CompletedTask;

                    },

                    OnUserInformationReceived = context =>
                    {
                        return Task.CompletedTask;

                    },

                    OnRemoteSignOut = context =>
                    {
                        return Task.CompletedTask;

                    },

                    OnAuthenticationFailed = context =>
                    {
                        return Task.CompletedTask;

                    },

                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
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

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
