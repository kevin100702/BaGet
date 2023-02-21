using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using BaGet.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Json.Serialization;

namespace BaGet.Web
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IOptionsSnapshot<BaGetOptions> _baGetOptions;

        public BasicAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IOptionsSnapshot<BaGetOptions> baGetOptions
            )
            : base(options, logger, encoder, clock)
        {
            _baGetOptions = baGetOptions;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // skip authentication if endpoint has [AllowAnonymous] attribute
            var endpoint = Context.GetEndpoint();
            if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
                return await Task.FromResult(AuthenticateResult.NoResult());

            if (!Request.Headers.ContainsKey("Authorization"))
            {
                Response.StatusCode = 401;
                Response.Headers.Add("WWW-Authenticate", "Basic realm=\"\", charset=\"UTF-8\"");
                return await Task.FromResult(AuthenticateResult.Fail("Missing Authorization Header"));
            }

            User user = null;
            try
            {
                var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
                var credentials = Encoding.UTF8.GetString(credentialBytes).Split(new[] { ':' }, 2);
                var username = credentials[0];
                var password = credentials[1];

                if (username != _baGetOptions.Value.Username || password != _baGetOptions.Value.Password)
                {
                    Response.StatusCode = 401;
                    Response.Headers.Add("WWW-Authenticate", "Basic realm=\"\", charset=\"UTF-8\"");
                    return await Task.FromResult(AuthenticateResult.Fail("The username or password is not correct."));
                }
                else
                    user = new User { Username = _baGetOptions.Value.Username, Password = _baGetOptions.Value.Password, Id = 1, FirstName = "Admin", LastName = "Admin" };

            }
            catch
            {
                Response.StatusCode = 401;
                Response.Headers.Add("WWW-Authenticate", "Basic realm=\"\", charset=\"UTF-8\"");
                return await Task.FromResult(AuthenticateResult.Fail("Invalid Authorization Header"));
            }

            if (user == null)
            {
                Response.StatusCode = 401;
                Response.Headers.Add("WWW-Authenticate", "Basic realm=\"\", charset=\"UTF-8\"");
                return await Task.FromResult(AuthenticateResult.Fail("Invalid Username or Password"));
            }
                

            var claims = new[] {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
            };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return await Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }

    public class User
    {
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Username { get; set; }

        [JsonIgnore]
        public string Password { get; set; }
    }
}
