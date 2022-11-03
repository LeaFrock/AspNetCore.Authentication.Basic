# LeaFLib.AspNetCore.Authentication.Basic

<img width="128px" height="128px" src="https://raw.githubusercontent.com/LeaFrock/LeaFLib/main/leaf.png" align="right"/> 

[![LeaFLib.AspNetCore.Authentication.Basic](https://img.shields.io/nuget/v/LeaFLib.AspNetCore.Authentication.Basic.svg?color=green)](https://www.nuget.org/packages/LeaFLib.AspNetCore.Authentication.Basic/)
[![LeaFLib.AspNetCore.Authentication.Basic](https://img.shields.io/nuget/dt/LeaFLib.AspNetCore.Authentication.Basic.svg?color=red)](https://www.nuget.org/packages/LeaFLib.AspNetCore.Authentication.Basic/)
[![.NET Release](https://github.com/LeaFrock/AspNetCore.Authentication.Basic/actions/workflows/dotnet.yml/badge.svg?branch=main)](https://github.com/LeaFrock/AspNetCore.Authentication.Basic/actions/workflows/dotnet.yml)

A Basic Authentication library for ASP.NET Core.

Currently Basic Authentication is not recommended for online productions, but it's still useful for testing or internal systems due to its easiness.

## Usage

### Implement `IBasicUserAuthenticator`

You must provide an implementation of `IBasicUserAuthenticator`. Take the following for example,

```csharp
    internal sealed class SampleBasicUserAuthenticator : IBasicUserAuthenticator
    {
        private readonly ApplicationDbContext _efContext; // Use EF Core

        public SampleBasicUserAuthenticator(ApplicationDbContext dbContext)
        {
            _efContext = dbContext;
        }

        public async Task<List<Claim>?> AuthenticateUser(string username, string password)
        {
            var user = await _efContext.Users
                .AsNoTracking()
                .Where(u => u.Account == username)
                .FirstOrDefaultAsync();
            if (user is null)
            {
                return default;
            }
            if (user.Password != password)
            {
                return new();
            }
            return new()
            {
                new(ClaimTypes.NameIdentifier, user.Account),
            };
        }
    }
```

### Use DI extensions

Use `AddBasic` extensions for `AuthenticationBuilder`. Take the following for example,

```csharp
builder.Services
    .AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme)
    .AddBasic<SampleBasicUserAuthenticator>(opt => opt.Realm = "Blazor App");
```

You can also refer to the samples in this repo.

## Contribution

If you encounter any problems in the process, feel free to ask for help with an issue.