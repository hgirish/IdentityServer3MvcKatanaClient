using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

namespace KatanaClient
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            string baseAddress = "https://localhost:44333/core";
            string tokenEndpoint = baseAddress + "/connect/token";
            string userInfoEndpoint = baseAddress + "/connect/userinfo";
            string clientAddress = "https://localhost:44302/";
            

            JwtSecurityTokenHandler.InboundClaimTypeMap = 
                new Dictionary<string, string>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions()
            {
                ClientId = "katanaclient",
                Authority = baseAddress,
                RedirectUri = clientAddress,
                PostLogoutRedirectUri = clientAddress,
                ResponseType = "code id_token",
                Scope = "openid profile roles read write offline_access",
                SignInAsAuthenticationType = "Cookies",

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = async n =>
                    {
                        var tokenClient = new TokenClient(
                            tokenEndpoint,
                            "katanaclient",
                            "secret");

                        var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(
                            n.Code, n.RedirectUri);

                        if (tokenResponse.AccessToken != null)
                        {
                            var userInfoClient = new UserInfoClient(
                                new Uri(userInfoEndpoint), tokenResponse.AccessToken);

                            var userInfoResponse = await userInfoClient.GetAsync();

                            var id = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType);
                            var userClaims = userInfoResponse.GetClaimsIdentity().Claims.ToList();
                            
                            if (userClaims.Any())
                            {
                                id.AddClaims(userClaims);
                                foreach (var claim in userClaims.Where(x => x.Type == "role"))
                                {
                                    id.AddClaim(new Claim(ClaimTypes.Role, claim.Value));
                                }
                            }
                            if (tokenResponse.AccessToken != null)
                                id.AddClaim(new Claim("access_token", tokenResponse.AccessToken));

                            var localExpiresIn = DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime();
                            if (localExpiresIn != null)
                            {
                                id.AddClaim(new Claim("expires_at",
                                    localExpiresIn
                                        .ToString(CultureInfo.InvariantCulture)));
                            }
                        
                            if (tokenResponse.RefreshToken != null)
                                id.AddClaim(new Claim("refresh_token", tokenResponse.RefreshToken));
                            if (n.ProtocolMessage.IdToken != null)
                                id.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                            id.AddClaim(new Claim("sid", n.AuthenticationTicket.Identity
                                .FindFirst("sid").Value));

                            n.AuthenticationTicket = new AuthenticationTicket(
                                new ClaimsIdentity(id.Claims,
                                    n.AuthenticationTicket.Identity.AuthenticationType),
                                n.AuthenticationTicket.Properties);
                        }
                    },
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                        {
                            var idTokenHint = n.OwinContext.Authentication.User
                                .FindFirst("id_token");
                            if (idTokenHint != null)
                            {
                                n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                            }
                        }
                        return Task.FromResult(0);
                    }
                }

            });
        }
    }
}