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