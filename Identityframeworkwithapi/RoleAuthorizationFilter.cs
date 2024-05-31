using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace Identityframeworkwithapi
{
    public class RoleAuthorizationFilter : IAuthorizationFilter
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<RoleAuthorizationFilter> _logger;

            public RoleAuthorizationFilter(IConfiguration configuration, ILogger<RoleAuthorizationFilter> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            // Get the JWT token from the request headers
            var authHeader = context.HttpContext.Request.Headers["Authorization"];
            if (authHeader.Count == 0)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            var authHeaderValue = authHeader[0];
            if (!authHeaderValue.StartsWith("Bearer "))
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            var token = authHeaderValue.Substring("Bearer ".Length).Trim();

            // Validate and decode the JWT token
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Issuer"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            // Validate the token
            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

                // Check if the user has the required role
                if (principal.HasClaim(ClaimTypes.Role, "Admin"))
                {
                    // User is authorized
                    _logger.LogInformation("Authorized");
                    context.HttpContext.User = principal; // Set the principal in the HttpContext
                }
                else
                {
                    // User is not authorized
                    context.Result = new UnauthorizedResult();
                }
            }
            catch (Exception ex)
            {
                // Token validation failed
                _logger.LogError(ex, "Token validation failed");
                context.Result = new UnauthorizedResult();
            }
        }
    }
}
