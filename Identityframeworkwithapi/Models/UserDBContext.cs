using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Identityframeworkwithapi.Models
{
    public class UserDBContext: IdentityDbContext<User>
    {
        public UserDBContext(DbContextOptions<UserDBContext> options)
      : base(options)
        {

        }
    }
}
