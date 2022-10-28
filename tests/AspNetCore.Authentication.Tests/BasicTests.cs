using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Basic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Microsoft.AspNetCore.Authentication
{
    public class BasicTests : SharedAuthenticationTests<BasicAuthenticationOptions>
    {
        protected override string DefaultScheme => BasicAuthenticationDefaults.AuthenticationScheme;

        protected override Type HandlerType => typeof(BasicAuthenticationHandler);

        protected override void RegisterAuth(AuthenticationBuilder services, Action<BasicAuthenticationOptions> configure)
        {
            services.AddBasic(o =>
            {
                ConfigureDefaults(o);
                configure.Invoke(o);
            });
        }

        private static void ConfigureDefaults(BasicAuthenticationOptions o)
        {
            o.Realm = "Test";
        }

        private static async Task<IHost> CreateHost(Action<BasicAuthenticationOptions>? options = null, Func<HttpContext, Func<Task>, Task>? handlerBeforeAuth = null)
        {
            var host = new HostBuilder()
                .ConfigureWebHost(builder =>
                    builder.UseTestServer()
                        .Configure(app =>
                        {
                            if (handlerBeforeAuth != null)
                            {
                                app.Use(handlerBeforeAuth);
                            }

                            app.UseAuthentication();
                            app.Use(async (context, next) =>
                            {
                                if (context.Request.Path == new PathString("/checkforerrors"))
                                {
                                    var result = await context.AuthenticateAsync(BasicAuthenticationDefaults.AuthenticationScheme); // this used to be "Automatic"
                                    if (result.Failure != null)
                                    {
                                        throw new Exception("Failed to authenticate", result.Failure);
                                    }
                                    return;
                                }
                                else if (context.Request.Path == new PathString("/oauth"))
                                {
                                    if (context.User == null ||
                                        context.User.Identity == null ||
                                        !context.User.Identity.IsAuthenticated)
                                    {
                                        context.Response.StatusCode = 401;
                                        // REVIEW: no more automatic challenge
                                        await context.ChallengeAsync(BasicAuthenticationDefaults.AuthenticationScheme);
                                        return;
                                    }

                                    var identifier = context.User.FindFirst(ClaimTypes.NameIdentifier);
                                    if (identifier == null)
                                    {
                                        context.Response.StatusCode = 500;
                                        return;
                                    }

                                    await context.Response.WriteAsync(identifier.Value);
                                }
                                else if (context.Request.Path == new PathString("/token"))
                                {
                                    var token = await context.GetTokenAsync("access_token");
                                    await context.Response.WriteAsync(token!);
                                }
                                else if (context.Request.Path == new PathString("/unauthorized"))
                                {
                                    // Simulate Authorization failure
                                    var result = await context.AuthenticateAsync(BasicAuthenticationDefaults.AuthenticationScheme);
                                    await context.ChallengeAsync(BasicAuthenticationDefaults.AuthenticationScheme);
                                }
                                else if (context.Request.Path == new PathString("/forbidden"))
                                {
                                    // Simulate Forbidden
                                    await context.ForbidAsync(BasicAuthenticationDefaults.AuthenticationScheme);
                                }
                                else if (context.Request.Path == new PathString("/signIn"))
                                {
                                    await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(BasicAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal()));
                                }
                                else if (context.Request.Path == new PathString("/signOut"))
                                {
                                    await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync(BasicAuthenticationDefaults.AuthenticationScheme));
                                }
                                else if (context.Request.Path == new PathString("/expiration"))
                                {
                                    var authenticationResult = await context.AuthenticateAsync(BasicAuthenticationDefaults.AuthenticationScheme);
                                    await context.Response.WriteAsJsonAsync(
                                        new { Expires = authenticationResult.Properties?.ExpiresUtc, Issued = authenticationResult.Properties?.IssuedUtc });
                                }
                                else
                                {
                                    await next(context);
                                }
                            });
                        })
                        .ConfigureServices(services => services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme).AddBasic(options!)))
                .Build();

            await host.StartAsync();
            return host;
        }
    }
}