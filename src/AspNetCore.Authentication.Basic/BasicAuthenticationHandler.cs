using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Microsoft.AspNetCore.Authentication.Basic
{
    /// <summary>
    /// An <see cref="AuthenticationHandler{TOptions}"/> that can perform Basic authentication.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7617"/> for details.
    /// </remarks>
    public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        private readonly IBasicUserAuthenticator _userAuthenticator;

        /// <summary>
        /// Initializes a new instance of <see cref="BasicAuthenticationHandler"/>.
        /// </summary>
        /// <inheritdoc />
        public BasicAuthenticationHandler(
            IOptionsMonitor<BasicAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IBasicUserAuthenticator userAuthenticator) : base(options, logger, encoder, clock)
        {
            _userAuthenticator = userAuthenticator;
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        private new BasicAuthenticationEvents Events
        {
            get => (BasicAuthenticationEvents)base.Events!;
            set => base.Events = value;
        }

        /// <inheritdoc />
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new BasicAuthenticationEvents());

        /// <summary>
        /// Searches the 'Authorization' header for a 'Basic' token.
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string? token;
            try
            {
                // Give application opportunity to find from a different location, adjust, or reject token
                var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);

                // event can set the token
                await Events.MessageReceived(messageReceivedContext);
                if (messageReceivedContext.Result != null)
                {
                    return messageReceivedContext.Result;
                }

                // If application retrieved token from somewhere else, use that.
                token = messageReceivedContext.Token;

                if (string.IsNullOrEmpty(token))
                {
                    string authorization = Request.Headers.Authorization.ToString();

                    // If no authorization header found, nothing to process further
                    if (string.IsNullOrEmpty(authorization))
                    {
                        return AuthenticateResult.NoResult();
                    }

                    if (authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                    {
                        token = authorization["Basic ".Length..].Trim();
                    }

                    // If no token found, no further work possible
                    if (string.IsNullOrEmpty(token))
                    {
                        return AuthenticateResult.NoResult();
                    }
                }

                string plainText = string.Empty;
                try
                {
                    var bytes = Convert.FromBase64String(token);
                    plainText = Encoding.UTF8.GetString(bytes).Trim();
                }
                catch (Exception ex)
                {
                    return await AuthenticationFailed(ex, default);
                }

                int separator = plainText.IndexOf(':');
                if (separator < 0)
                {
                    return await AuthenticationFailed(default, "Missing separator ':'");
                }

                string username, password;
                if (separator == 0)
                {
                    username = string.Empty;
                    password = plainText;
                }
                else if (separator == plainText.Length - 1)
                {
                    username = plainText;
                    password = string.Empty;
                }
                else
                {
                    username = plainText[0..separator];
                    password = plainText[(separator + 1)..];
                }

                List<Claim>? claims;
                try
                {
                    claims = await _userAuthenticator.AuthenticateUser(username, password);
                }
                catch (Exception ex)
                {
                    Logger.UserAuthenticatedFailed(ex);

                    return await AuthenticationFailed(ex, default);
                }

                if (claims is null || claims.Count < 1)
                {
                    return await AuthenticationFailed(default, "Invalid user or password.");
                }

                Logger.UserAuthenticatedSucceeded();

                ClaimsIdentity identity = new(claims, Scheme.Name);
                ClaimsPrincipal principal = new(identity);

                var userAuthenticatedContext = new UserAuthenticatedContext(Context, Scheme, Options)
                {
                    Principal = principal,
                };

                await Events.UserAuthenticated(userAuthenticatedContext);

                if (userAuthenticatedContext.Result != null)
                {
                    return userAuthenticatedContext.Result;
                }

                userAuthenticatedContext.Success();
                return userAuthenticatedContext.Result!;
            }
            catch (Exception ex)
            {
                Logger.ErrorProcessingMessage(ex);

                var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = ex,
                };

                await Events.AuthenticationFailed(authenticationFailedContext);
                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                throw;
            }
        }

        /// <inheritdoc />
        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.Headers.Append(HeaderNames.WWWAuthenticate, Options.GetWWWAuthenticate());
            return base.HandleChallengeAsync(properties);
        }

        private async Task<AuthenticateResult> AuthenticationFailed(Exception? exception, string? error)
        {
            var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
            {
                Exception = exception,
            };
            if (error is not null)
            {
                authenticationFailedContext.ErrorIfNoException = error;
            }

            await Events.AuthenticationFailed(authenticationFailedContext);
            if (authenticationFailedContext.Result != null)
            {
                return authenticationFailedContext.Result;
            }

            authenticationFailedContext.Fail();
            return authenticationFailedContext.Result!;
        }
    }
}