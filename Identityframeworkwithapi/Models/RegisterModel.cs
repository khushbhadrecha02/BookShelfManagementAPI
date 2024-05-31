namespace Identityframeworkwithapi.Models
{
    public class RegisterModel
    {
        public string? Email { get; set; }
        public string? Password { get; set; }
        public IList<string>? Roles { get; set; }
        public string? Role { get; set; }
        public string? UserName { get; set; }   
    }
}
