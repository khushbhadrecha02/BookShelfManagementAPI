using Microsoft.AspNetCore.Identity;

namespace Identityframeworkwithapi.Models
{
    public class User:IdentityUser
    {
        public string? PhotoPath { get; set; }   
    }
}
