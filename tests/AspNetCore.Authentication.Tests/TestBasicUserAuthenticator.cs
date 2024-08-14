using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Basic;

namespace AspNetCore.Authentication.Tests
{
    internal class TestBasicUserAuthenticator : IBasicUserAuthenticator
    {
        private static readonly Dictionary<string, User> Users = new(StringComparer.InvariantCultureIgnoreCase)
        {
            { "Alice",  new(){ Account = "alice@example.com", Password = "123456"} },
        };

        public async Task<List<Claim>?> AuthenticateUser(string username, string password)
        {
            if (!Users.TryGetValue(username, out var user))
            {
                return default;
            }
            if (user.Password != password)
            {
                return [];
            }
            await Task.Delay(40); // Mock database request
            return
            [
                new(ClaimTypes.NameIdentifier, user.Account),
            ];
        }

        private sealed class User
        {
            public string Account { get; set; } = string.Empty;

            public string Password { get; set; } = string.Empty;
        }
    }
}