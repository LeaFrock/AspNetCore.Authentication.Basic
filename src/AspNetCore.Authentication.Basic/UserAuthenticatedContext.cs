using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authentication.Basic
{
    /// <summary>
    /// A context for <see cref="BasicAuthenticationEvents.OnUserAuthenticated"/>.
    /// </summary>
    public class UserAuthenticatedContext : ResultContext<BasicAuthenticationOptions>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="UserAuthenticatedContext"/>.
        /// </summary>
        /// <inheritdoc />
        public UserAuthenticatedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            BasicAuthenticationOptions options)
            : base(context, scheme, options) { }
    }
}