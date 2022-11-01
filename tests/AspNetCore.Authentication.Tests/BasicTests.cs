using System.Net;
using System.Security.Claims;
using System.Text;
using AspNetCore.Authentication.Tests;
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

        protected override void RegisterAuth(AuthenticationBuilder builder, Action<BasicAuthenticationOptions>? configure)
        {
            builder.AddBasic<TestBasicUserAuthenticator>(o =>
            {
                ConfigureDefaults(o);
                configure?.Invoke(o);
            });
        }

        [Fact]
        public async Task SignInThrows()
        {
            using var host = await CreateHost();
            using var server = host.GetTestServer();
            var rsp = await SendAsync(server, "https://example.com/signIn");
            Assert.Equal(HttpStatusCode.OK, rsp.StatusCode);
        }

        [Fact]
        public async Task SignOutThrows()
        {
            using var host = await CreateHost();
            using var server = host.GetTestServer();
            var rsp = await SendAsync(server, "https://example.com/signOut");
            Assert.Equal(HttpStatusCode.OK, rsp.StatusCode);
        }

        [Fact]
        public async Task ThrowAtAuthenticationFailedEvent()
        {
            using var host = await CreateHost(o =>
            {
                o.Events = new BasicAuthenticationEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        context.Response.StatusCode = 401;
                        throw new Exception();
                    },
                    OnMessageReceived = context =>
                    {
                        context.Token = "something";
                        return Task.FromResult(0);
                    }
                };
            },
            async (context, next) =>
            {
                try
                {
                    await next();
                    Assert.False(true, "Expected exception is not thrown");
                }
                catch (Exception)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("i got this");
                }
            });

            using var server = host.GetTestServer();
            var rsp = await SendAsync(server, "https://example.com/signIn");

            Assert.Equal(HttpStatusCode.Unauthorized, rsp.StatusCode);
        }

        [Fact]
        public async Task EmptyRealmOption()
        {
            using var host = await CreateHost(opt => opt.Realm = "");
            using var server = host.GetTestServer();
            await Assert.ThrowsAsync<ArgumentException>(nameof(BasicAuthenticationOptions.Realm), () => SendAsync(server, "http://example.com/basicauth"));
        }

        [Fact]
        public async Task InvalidCharSetOption()
        {
            using var host = await CreateHost(opt => opt.CharSet = "gbk");
            using var server = host.GetTestServer();
            await Assert.ThrowsAsync<ArgumentException>(nameof(BasicAuthenticationOptions.CharSet), () => SendAsync(server, "http://example.com/basicauth"));
        }

        [Theory]
        [InlineData("Alice", "123456", HttpStatusCode.OK)]
        [InlineData("Alice", "", HttpStatusCode.Unauthorized)]
        [InlineData("Bob", "123456", HttpStatusCode.Unauthorized)]
        [InlineData("", "", HttpStatusCode.Unauthorized)]
        public async Task HeaderReceived(string username, string password, HttpStatusCode statusCode)
        {
            string token = GenerateBasicHeader(username, password);
            using var host = await CreateHost();
            using var server = host.GetTestServer();
            using var rsp = await SendAsync(server, "https://example.com/basicauth", token);
            Assert.Equal(statusCode, rsp.StatusCode);
            if (statusCode == HttpStatusCode.OK)
            {
                string rspText = await rsp.Content.ReadAsStringAsync();
                Assert.Equal("alice@example.com", rspText);
            }
        }

        [Fact]
        public async Task NoHeaderReceived()
        {
            using var host = await CreateHost();
            using var server = host.GetTestServer();
            var rsp = await SendAsync(server, "http://example.com/basicauth");
            var wwwAuthenticate = rsp.Headers.WwwAuthenticate.First();
            Assert.Equal(HttpStatusCode.Unauthorized, rsp.StatusCode);
            Assert.Equal(BasicAuthenticationDefaults.AuthenticationScheme, wwwAuthenticate.Scheme);
            Assert.Equal("realm=\"Test\", charset=\"UTF-8\"", wwwAuthenticate.Parameter);
        }

        [Fact]
        public async Task HeaderWithoutBasicReceived()
        {
            using var host = await CreateHost();
            using var server = host.GetTestServer();
            var rsp = await SendAsync(server, "http://example.com/basicauth", "Token");
            Assert.Equal(HttpStatusCode.Unauthorized, rsp.StatusCode);
        }

        [Fact]
        public async Task InvalidTokenReceived()
        {
            using var host = await CreateHost();
            using var server = host.GetTestServer();
            var rsp = await SendAsync(server, "http://example.com/basicauth", "Basic someblob");
            var rspText = await rsp.Content.ReadAsStringAsync();
            var wwwAuthenticate = rsp.Headers.WwwAuthenticate.First();
            Assert.Equal(HttpStatusCode.Unauthorized, rsp.StatusCode);
            Assert.Equal(BasicAuthenticationDefaults.AuthenticationScheme, wwwAuthenticate.Scheme);
            Assert.Equal("realm=\"Test\", charset=\"UTF-8\"", wwwAuthenticate.Parameter);
            Assert.Equal(string.Empty, rspText);
        }

        [Fact]
        public async Task RetrievingTokenFromAlternateLocation()
        {
            using var host = await CreateHost(options =>
            {
                options.Events = new BasicAuthenticationEvents()
                {
                    OnMessageReceived = context =>
                    {
                        context.Token = GenerateBasicToken("Alice", "123456");
                        return Task.CompletedTask;
                    }
                };
            });

            using var server = host.GetTestServer();
            var rsp = await SendAsync(server, "http://example.com/basicauth");
            var rspText = await rsp.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.OK, rsp.StatusCode);
            Assert.Equal("alice@example.com", rspText);
        }

        [Fact]
        public async Task EventOnMessageReceivedSkip_NoMoreEventsExecuted()
        {
            using var host = await CreateHost(options =>
            {
                options.Events = new BasicAuthenticationEvents()
                {
                    OnMessageReceived = context =>
                    {
                        context.NoResult();
                        return Task.FromResult(0);
                    },
                    OnAuthenticationFailed = context =>
                    {
                        throw new NotImplementedException(context.Exception!.ToString());
                    },
                    OnUserAuthenticated = context =>
                    {
                        throw new NotImplementedException();
                    },
                };
            });

            using var server = host.GetTestServer();
            var rsp = await SendAsync(server, "http://example.com/checkforerrors", "Basic Token");
            var rspText = await rsp.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.OK, rsp.StatusCode);
            Assert.Equal(string.Empty, rspText);
        }

        [Fact]
        public async Task EventOnMessageReceivedReject_NoMoreEventsExecuted()
        {
            using var host = await CreateHost(options =>
            {
                options.Events = new BasicAuthenticationEvents()
                {
                    OnMessageReceived = context =>
                    {
                        context.Fail("Authentication was aborted from user code.");
                        context.Response.StatusCode = StatusCodes.Status202Accepted;
                        return Task.FromResult(0);
                    },
                    OnAuthenticationFailed = context =>
                    {
                        throw new NotImplementedException(context.Exception!.ToString());
                    },
                    OnUserAuthenticated = context =>
                    {
                        throw new NotImplementedException();
                    },
                };
            });

            using var server = host.GetTestServer();
            var exception = await Assert.ThrowsAsync<Exception>(() => SendAsync(server, "http://example.com/checkforerrors", "Basic Token"));

            Assert.Equal("Authentication was aborted from user code.", exception.InnerException!.Message);
        }

        [Fact]
        public async Task EventOnAuthenticationFailedSkip_NoMoreEventsExecuted()
        {
            using var host = await CreateHost(options =>
            {
                options.Events = new BasicAuthenticationEvents()
                {
                    OnAuthenticationFailed = context =>
                    {
                        context.NoResult();
                        return Task.FromResult(0);
                    },
                };
            });

            using var server = host.GetTestServer();
            var rsp = await SendAsync(server, "http://example.com/checkforerrors", "Basic Token");
            var rspText = await rsp.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.OK, rsp.StatusCode);
            Assert.Equal(string.Empty, rspText);
        }

        [Fact]
        public async Task EventOnAuthenticationFailedReject_NoMoreEventsExecuted()
        {
            using var host = await CreateHost(options =>
            {
                options.Events = new BasicAuthenticationEvents()
                {
                    OnAuthenticationFailed = context =>
                    {
                        context.Fail("Authentication was aborted from user code.");
                        context.Response.StatusCode = StatusCodes.Status202Accepted;
                        return Task.FromResult(0);
                    },
                };
            });

            using var server = host.GetTestServer();
            var exception = await Assert.ThrowsAsync<Exception>(() => SendAsync(server, "http://example.com/checkforerrors", "Basic Token"));

            Assert.Equal("Authentication was aborted from user code.", exception.InnerException!.Message);
        }

        [Fact]
        public async Task EventOnUserAuthenticatedSkip_NoMoreEventsExecuted()
        {
            using var host = await CreateHost(options =>
            {
                options.Events = new BasicAuthenticationEvents()
                {
                    OnUserAuthenticated = context =>
                    {
                        context.NoResult();
                        return Task.FromResult(0);
                    },
                };
            });

            using var server = host.GetTestServer();
            var authz = GenerateBasicHeader("Alice", "123456");
            var rsp = await SendAsync(server, "http://example.com/checkforerrors", authz);
            var rspText = await rsp.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.OK, rsp.StatusCode);
            Assert.Equal(string.Empty, rspText);
        }

        [Fact]
        public async Task EventOnUserAuthenticatedReject_NoMoreEventsExecuted()
        {
            using var host = await CreateHost(options =>
            {
                options.Events = new BasicAuthenticationEvents()
                {
                    OnUserAuthenticated = context =>
                    {
                        context.Fail("Authentication was aborted from user code.");
                        context.Response.StatusCode = StatusCodes.Status202Accepted;
                        return Task.FromResult(0);
                    },
                };
            });

            using var server = host.GetTestServer();
            var authz = GenerateBasicHeader("Alice", "123456");
            var exception = await Assert.ThrowsAsync<Exception>(() => SendAsync(server, "http://example.com/checkforerrors", authz));

            Assert.Equal("Authentication was aborted from user code.", exception.InnerException!.Message);
        }

        private static void ConfigureDefaults(BasicAuthenticationOptions o)
        {
            o.Realm = "Test";
        }

        private async Task<IHost> CreateHost(Action<BasicAuthenticationOptions>? options = null, Func<HttpContext, Func<Task>, Task>? handlerBeforeAuth = null)
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
                                else if (context.Request.Path == new PathString("/basicauth"))
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
                                else
                                {
                                    await next(context);
                                }
                            });
                        })
                        .ConfigureServices(services =>
                        {
                            var builder = services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme);
                            RegisterAuth(builder, options);
                        }))
                .Build();

            await host.StartAsync();
            return host;
        }

        private static Task<HttpResponseMessage> SendAsync(TestServer server, string uri, string? authorizationHeader = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (!string.IsNullOrEmpty(authorizationHeader))
            {
                request.Headers.Add("Authorization", authorizationHeader);
            }
            var client = server.CreateClient();
            return client.SendAsync(request);
        }

        private static string GenerateBasicHeader(string username, string password)
        {
            var token = GenerateBasicToken(username, password);
            return $"{BasicAuthenticationDefaults.AuthenticationScheme} {token}";
        }

        private static string GenerateBasicToken(string username, string password)
        {
            var bytes = Encoding.UTF8.GetBytes($"{username}:{password}");
            return Convert.ToBase64String(bytes);
        }
    }
}