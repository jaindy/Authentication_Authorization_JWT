using AuthWEBAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthWEBAPI.Data
{
    public class MyDbContext: DbContext
    {
        public MyDbContext(DbContextOptions<MyDbContext> options):base(options) { }
        public DbSet<User> Users { get; set; }
            
        
    }
}
