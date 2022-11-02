using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Basic;
using Microsoft.EntityFrameworkCore;

namespace Blazor4BasicAuth.Server
{
    internal sealed class SampleBasicUserAuthenticator : IBasicUserAuthenticator
    {
        private readonly ApplicationDbContext _efContext;

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

        private sealed class User
        {
            public string Account { get; set; } = string.Empty;

            public string Password { get; set; } = string.Empty;
        }
    }
}