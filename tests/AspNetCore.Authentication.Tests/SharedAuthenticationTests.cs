// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Microsoft.AspNetCore.Authentication;

public abstract class SharedAuthenticationTests<TOptions> where TOptions : AuthenticationSchemeOptions
{
    protected abstract string DefaultScheme { get; }
    protected virtual string? DisplayName { get; }
    protected abstract Type HandlerType { get; }

    protected abstract void RegisterAuth(AuthenticationBuilder services, Action<TOptions> configure);

    [Fact]
    public async Task VerifySchemeDefaults()
    {
        var services = new ServiceCollection().ConfigureAuthTestServices();
        var builder = services.AddAuthentication();
        RegisterAuth(builder, o => { });
        var sp = services.BuildServiceProvider();
        var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
        var scheme = await schemeProvider.GetSchemeAsync(DefaultScheme);
        Assert.NotNull(scheme);
        Assert.Equal(HandlerType, scheme.HandlerType);
        Assert.Equal(DisplayName, scheme.DisplayName);
    }
}