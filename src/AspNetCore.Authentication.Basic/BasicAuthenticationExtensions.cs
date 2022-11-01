using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Authentication.Basic
{
    /// <summary>
    /// Extension methods to configure Basic authentication.
    /// </summary>
    public static class BasicAuthenticationExtensions
    {
        /// <summary>
        /// Enables Basic authentication using the default scheme <see cref="BasicAuthenticationDefaults.AuthenticationScheme"/>.
        /// <para>
        /// Basic authentication performs authentication by extracting and validating a Base64 token from the <c>Authorization</c> request header.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddBasic<TAuthenticator>(this AuthenticationBuilder builder)
            where TAuthenticator : class, IBasicUserAuthenticator
            => builder.AddBasic<TAuthenticator>(BasicAuthenticationDefaults.AuthenticationScheme, _ => { });

        /// <summary>
        /// Enables Basic authentication using a pre-defined scheme.
        /// <para>
        /// Basic authentication performs authentication by extracting and validating a Base64 token from the <c>Authorization</c> request header.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddBasic<TAuthenticator>(this AuthenticationBuilder builder, string authenticationScheme)
            where TAuthenticator : class, IBasicUserAuthenticator
            => builder.AddBasic<TAuthenticator>(authenticationScheme, _ => { });

        /// <summary>
        /// Enables Basic authentication using the default scheme <see cref="BasicAuthenticationDefaults.AuthenticationScheme"/>.
        /// <para>
        /// Basic authentication performs authentication by extracting and validating a Base64 token from the <c>Authorization</c> request header.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="configureOptions">A delegate that allows configuring <see cref="BasicAuthenticationOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddBasic<TAuthenticator>(this AuthenticationBuilder builder, Action<BasicAuthenticationOptions> configureOptions)
            where TAuthenticator : class, IBasicUserAuthenticator
            => builder.AddBasic<TAuthenticator>(BasicAuthenticationDefaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Enables Basic authentication using the specified scheme.
        /// <para>
        /// Basic authentication performs authentication by extracting and validating a Base64 token from the <c>Authorization</c> request header.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">A delegate that allows configuring <see cref="BasicAuthenticationOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddBasic<TAuthenticator>(this AuthenticationBuilder builder, string authenticationScheme, Action<BasicAuthenticationOptions> configureOptions)
            where TAuthenticator : class, IBasicUserAuthenticator
            => builder.AddBasic<TAuthenticator>(authenticationScheme, displayName: null, configureOptions: configureOptions);

        /// <summary>
        /// Enables Basic authentication using the specified scheme.
        /// <para>
        /// Basic authentication performs authentication by extracting and validating a Base64 token from the <c>Authorization</c> request header.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">The display name for the authentication handler.</param>
        /// <param name="configureOptions">A delegate that allows configuring <see cref="BasicAuthenticationOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddBasic<TAuthenticator>(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<BasicAuthenticationOptions> configureOptions)
            where TAuthenticator : class, IBasicUserAuthenticator
        {
            builder.Services.AddTransient<IBasicUserAuthenticator, TAuthenticator>();
            return builder.AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}