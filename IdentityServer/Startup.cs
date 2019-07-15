// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

namespace IdentityServer
{
    public class Startup
    {
        public IHostingEnvironment Environment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IHostingEnvironment environment, IConfiguration configuration)
        {
            Environment = environment;
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {

            services.AddMvc().SetCompatibilityVersion(Microsoft.AspNetCore.Mvc.CompatibilityVersion.Version_2_1);

            var builder = services.AddIdentityServer()
                .AddInMemoryIdentityResources(Config.GetIdentityResources())
                .AddInMemoryApiResources(Config.GetApis())
                .AddInMemoryClients(Config.GetClients());

            //services.AddOidcStateDataFormatterCache();

            //services.AddAuthentication().AddOAuth("AdfsOAuth", "EIMAS OAuth", options =>
            //{
            //    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            //    options.SaveTokens = true;
            //    options.ClientId = "b33eb921-d242-4f1c-9892-3aa99fd59971";
            //    options.ClientSecret = "rssfJPdeWeTM8bmZRnV5kFyy_RcAQq5RJ_1vGtvo";                
            //    options.AuthorizationEndpoint = "https://dev-connect.eurofins.local/adfs/oauth2/authorize";
            //    options.TokenEndpoint = "https://dev-connect.eurofins.local/adfs/oauth2/token";
            //    options.UserInformationEndpoint = "https://dev-connect.eurofins.local/adfs/userinfo";
            //    options.CallbackPath = "/signin-adfs";                
            //    options.Scope.Add("openid");
            //    options.Scope.Add("profile");
            //    options.Scope.Add("allatclaims");
            //    options.Scope.Add("email");
            //    options.Scope.Add("http://localhost:5000/");

            //    options.Events = new OAuthEvents
            //    {
            //        OnCreatingTicket = async context =>
            //        {
            //            var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
            //            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
            //            //request.Headers.Add("x-li-format", "json");

            //            var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
            //            response.EnsureSuccessStatusCode();
            //            var user = JObject.Parse(await response.Content.ReadAsStringAsync());

            //            var email = user.Value<string>("emailAddress");
            //            if (!string.IsNullOrEmpty(email))
            //            {
            //                context.Identity.AddClaim(new Claim(ClaimTypes.Email, email, ClaimValueTypes.String,
            //                    context.Options.ClaimsIssuer));
            //            }

            //        }
            //    };
            //});


            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddTransient<IPrincipal>(
                provider => provider.GetService<IHttpContextAccessor>().HttpContext.User);
            services.AddSingleton<IAuthHelper, AuthHelper>();
            services.AddTransient<IClaimsTransformation, ClaimsTransformer>();
            services.AddTransient<IProfileService, ProfileService>();

            services.AddAuthentication()
                .AddOpenIdConnect("AdfsOidc", "EIMAS OIDC", options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                    options.SaveTokens = false;

                    options.Authority = Configuration["EIMASConfiguration:Authority"];
                    options.ClientId = Configuration["EIMASConfiguration:ClientId"];
                    options.ClientSecret = Configuration["EIMASConfiguration:ClientSecret"];
                    options.ResponseType = "code id_token";

                    options.Scope.Clear();
                    options.Scope.Add("allatclaims");
                    options.Scope.Add("user_impersonation");
                    options.Scope.Add("profile");
                    options.Scope.Add("openid");
                    options.Resource = Configuration["EIMASConfiguration:Resource"];

                    //options.CallbackPath = "/signin-adfs";
                    //options.SignedOutCallbackPath = "/signout-callback-adfs";
                    //options.RemoteSignOutPath = "/signin-adfs";
                    //options.TokenValidationParameters = new TokenValidationParameters
                    //{
                    //    NameClaimType = "name",
                    //    RoleClaimType = "role"
                    //};                    

                    options.Events = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents
                    {


                        OnTokenValidated = async ctx =>
                        {

                            //await _claimsTransformer.TransformAsync(ctx.Principal);

                            //List<Claim> claims = new List<Claim>();
                            //claims.Add(new Claim(ClaimTypes.NameIdentifier, "itsme"));
                            //claims.Add(new Claim(ClaimTypes.Name, "meagain"));
                            //claims.Add(new Claim(ClaimTypes.Email, "me@me.com"));
                            //claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/myclaim1", "value1"));
                            //claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/myclaim2", "value2"));

                            //ctx.HttpContext.User.AddIdentity(new ClaimsIdentity(claims));

                            //ctx.Principal = new ClaimsPrincipal(ci);
                            // .Success() uses 
                            // 1. the principal just set above  
                            // 2. the context properties
                            // 3. the context scheme
                            // to create the underlying ticket
                            //ctx.Success();
                            await Task.FromResult(0);
                        },

                        OnAuthorizationCodeReceived = async ctx =>
                        {
                            var request = ctx.HttpContext.Request;
                            var currentUri = UriHelper.BuildAbsolute(request.Scheme, request.Host, request.PathBase, request.Path);
                            var credential = new ClientCredential(ctx.Options.ClientId, ctx.Options.ClientSecret);

                            var authContext = new AuthenticationContext(ctx.Options.Authority, false, new 
                                InMemoryTokenCache(ctx.Principal.Identity.Name));

                            var result = await authContext.AcquireTokenByAuthorizationCodeAsync(
                                ctx.ProtocolMessage.Code, new Uri(currentUri), credential, ctx.Options.Resource);

                            ctx.HandleCodeRedemption(result.AccessToken, result.IdToken);
                        }
                    };

                });

            if (Environment.IsDevelopment())
            {
                builder.AddDeveloperSigningCredential();
            }
            //else
            //{
            //    throw new Exception("need to configure key material");
            //}
        }

        public void Configure(IApplicationBuilder app)
        {
            //if (Environment.IsDevelopment())
            //{
            //    app.UseDeveloperExceptionPage();
            //}
            app.UseDeveloperExceptionPage();

            app.UseStaticFiles();
            app.UseIdentityServer();
            app.UseMvcWithDefaultRoute();
        }

    }

    public class ClaimsTransformer : IClaimsTransformation
    {
        private readonly IPrincipal Principal;
        private readonly IAuthHelper AuthHelper;
        public ClaimsTransformer(IPrincipal principal, IAuthHelper authHelper)
        {
            Principal = principal;
            AuthHelper = authHelper;
        }

        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var id = ((ClaimsIdentity)principal.Identity);

            var ci = new ClaimsIdentity(id.Claims, id.AuthenticationType, id.NameClaimType, id.RoleClaimType);
            ci.AddClaim(new Claim("CustomClaim:IdentityServer:AuthenticationTime", DateTime.Now.ToString()));
            var cp = new ClaimsPrincipal(ci);
            return Task.FromResult(cp);
        }
    }

    // Here we can add additional claims for the client applications.
    public class ProfileService : IProfileService
    {
        private readonly IPrincipal Principal;
        private readonly IAuthHelper AuthHelper;
        public ProfileService(IPrincipal principal, IAuthHelper authHelper)
        {
            Principal = principal;
            AuthHelper = authHelper;
        }

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            List<Claim> claims = new List<Claim>(AuthHelper.GetUserClaims(Principal.Identity.Name));
            claims.Add(new Claim("CustomClaim:ClientApplication:AuthenticationTime", DateTime.Now.ToString()));
            context.IssuedClaims.AddRange(claims);
            return Task.FromResult(0);
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            var user = context.Subject;
            context.IsActive = user != null;
            return Task.FromResult(0);
        }
    }
}