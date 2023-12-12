using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using CMOBackend.Helper;
using CMOBackend.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace CMOBackend
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

            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "CMOBackend", Version = "v1" });
            });

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(x =>
                {
                    x.MetadataAddress = "http://192.168.2.21:8081/realms/myrealm/.well-known/openid-configuration";
                    x.RequireHttpsMetadata = false; // only for dev
                    x.SaveToken = true;
                    x.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = "http://192.168.2.21:8081/auth/realms/myrealm",

                        ValidAudience = "account",
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ClockSkew = TimeSpan.FromMinutes(1),

                    };
                    x.Events = new JwtBearerEvents
                    {
                        OnTokenValidated = context =>
                        {
                            var accessToken = context.SecurityToken as JwtSecurityToken;
                            if (accessToken != null)
                            {
                                // Extract claims from the access token and add them to ClaimsPrincipal
                                var claims = accessToken.Claims.ToList();

                                var roleClaims = JsonHelper.Deserialize<RealmAccess>(claims.FirstOrDefault(c => c.Type == "realm_access")?.Value);

                                foreach (var role in roleClaims.Roles)
                                {
                                    claims.Add(new Claim(ClaimTypes.Role, role));
                                }

                                context.Principal.AddIdentity(new ClaimsIdentity(claims));
                            }

                            return Task.CompletedTask;
                        },
                        OnAuthenticationFailed = context =>
                        {
                            if (context.Exception is SecurityTokenExpiredException)
                            {
                                context.Fail("Token has expired");
                            }
                            else
                            {
                                context.Fail("Token validation failed");
                            }

                            return Task.CompletedTask;
                        }
                    };

                });

            services.AddCors(options => options.AddDefaultPolicy(
                app =>
                {
                    app.AllowAnyHeader();
                    app.AllowAnyMethod();
                    app.AllowAnyOrigin();
                }
        ));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "CMOBackend v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
