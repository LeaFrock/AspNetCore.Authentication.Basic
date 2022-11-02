using System.Security.Claims;

namespace Microsoft.AspNetCore.Authentication.Basic
{
    /// <summary>
    /// User authenticator for Basic
    /// </summary>
    public interface IBasicUserAuthenticator
    {
        /// <summary>
        /// Authenticate the user info
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        Task<List<Claim>?> AuthenticateUser(string username, string password);
    }
}