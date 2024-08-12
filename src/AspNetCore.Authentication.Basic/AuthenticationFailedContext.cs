using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authentication.Basic
{
    /// <summary>
    /// A <see cref="ResultContext{TOptions}"/> when authentication has failed.
    /// </summary>
    public class AuthenticationFailedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        BasicAuthenticationOptions options) : ResultContext<BasicAuthenticationOptions>(context, scheme, options)
    {

        /// <summary>
        /// Gets or sets the exception associated with the authentication failure.
        /// </summary>
        public Exception? Exception { get; set; }

        /// <summary>
        /// Gets or sets the error message. It's designed to show failure messages while <see cref="Exception"/> is <c>null</c>.
        /// </summary>
        public string ErrorIfNoException { get; set; } = string.Empty;

        internal void Fail()
        {
            if (Exception is null)
            {
                Fail(ErrorIfNoException);
            }
            else
            {
                Fail(Exception);
            }
        }
    }
}