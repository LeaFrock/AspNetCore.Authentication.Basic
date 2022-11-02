using Blazor4BasicAuth.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace Blazor4BasicAuth.Server
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users => Set<User>();
    }
}