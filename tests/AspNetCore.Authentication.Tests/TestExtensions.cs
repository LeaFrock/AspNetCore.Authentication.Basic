// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Authentication;

public static class TestExtensions
{
    public static IServiceCollection ConfigureAuthTestServices(this IServiceCollection services)
    {
        return services
            .AddOptions()
            .AddLogging()
            .AddSingleton<IConfiguration>(new ConfigurationManager());
    }
}