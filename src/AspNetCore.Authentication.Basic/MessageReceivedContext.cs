using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authentication.Basic
{
    /// <summary>
    /// A context for <see cref="BasicAuthenticationEvents.OnMessageReceived"/>.
    /// </summary>
    public class MessageReceivedContext : ResultContext<BasicAuthenticationOptions>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="MessageReceivedContext"/>.
        /// </summary>
        /// <inheritdoc />
        public MessageReceivedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            BasicAuthenticationOptions options)
            : base(context, scheme, options) { }

        /// <summary>
        /// Bearer Token. This will give the application an opportunity to retrieve a token from an alternative location.
        /// </summary>
        public string? Token { get; set; }
    }
}