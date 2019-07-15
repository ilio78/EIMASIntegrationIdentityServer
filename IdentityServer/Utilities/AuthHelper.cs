using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;

namespace IdentityServer
{
    public interface IAuthHelper
    {
        string GetIdToken(string userName);
        IEnumerable<Claim> GetUserClaims(string userName);
    }

    public class AuthHelper : IAuthHelper
    {
        public IConfiguration Configuration { get; }

        public AuthHelper(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public string GetIdToken(string userName)
        {
            if (string.IsNullOrEmpty(userName))
                return null;

            AuthenticationContext ac = new AuthenticationContext(Configuration["EIMASConfiguration:Authority"], false, new InMemoryTokenCache(userName));
            AuthenticationResult ar = ac.AcquireTokenSilentAsync(Configuration["EIMASConfiguration:Resource"], new ClientCredential(Configuration["EIMASConfiguration:ClientId"], Configuration["EIMASConfiguration:ClientSecret"]), UserIdentifier.AnyUser).Result;
            return ar.IdToken;
        }

        public IEnumerable<Claim> GetUserClaims(string userName)
        {
            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jsonToken = handler.ReadToken(GetIdToken(userName) ?? string.Empty) as JwtSecurityToken;
            return jsonToken?.Claims;
        }
    }
}
