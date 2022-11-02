namespace Blazor4BasicAuth.Server.Models
{
    public sealed class User
    {
        public int Id { get; set; }

        public string Account { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;
    }
}