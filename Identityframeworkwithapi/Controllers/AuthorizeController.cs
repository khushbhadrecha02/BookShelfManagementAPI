using Identityframeworkwithapi.Models;
using Identityframeworkwithapi.Services;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using NuGet.Common;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.Intrinsics.X86;
using System.Security.Claims;
using System.Text;

namespace Identityframeworkwithapi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    
    public class AuthorizeController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IBookService _bookService;
        private readonly IdentityFramewrokUsingApiContext identityFramewrokUsingApiContext;
        // Constructor
        public AuthorizeController(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            IConfiguration configuration,
            IBookService bookService,
            IdentityFramewrokUsingApiContext identityFramewrokUsingApiContext)
        {
            _userManager = userManager;
            Console.WriteLine(_userManager);
            _signInManager = signInManager;
            Console.WriteLine(_signInManager);
            _configuration = configuration;
            Console.WriteLine(_configuration);
            _bookService = bookService;
            this.identityFramewrokUsingApiContext = identityFramewrokUsingApiContext;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            var user1 = new User { UserName = model.UserName, Email = model.Email };
            var result = await _userManager.CreateAsync(user1, model.Password);

            if (result.Succeeded)
            {
                var confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user1);
                //var callbackUrl = Url.Action("ConfirmEmail", "Authorize", new { userId = user1.Id, token = confirmationToken }, protocol: HttpContext.Request.Scheme);
                //SendEmailAsync(model.Email, callbackUrl);
                // Assuming the "User" role exists, assign the new user to the "User" role
                await _userManager.AddToRoleAsync(user1, "User");

                return Ok(new { userId = user1.Id,token = confirmationToken });
            }

            return BadRequest(result.Errors);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(RegisterModel model)
        {
            // Check if the user exists
            var user = await _userManager.FindByEmailAsync(model.Email);
            Console.WriteLine(user);
            if (user != null)
            {
                // Attempt to sign in the user with the provided password
                var result = await _signInManager.PasswordSignInAsync(user, model.Password, isPersistent: false, lockoutOnFailure: false);

                if (result.Succeeded)

                {
                    // Optionally generate a JWT token or perform other actions upon successful login
                    model.Roles = await _userManager.GetRolesAsync(user);
                   var token= GenerateJwtToken(model);
                    return Ok(new { Message = "Login successful!" , _token = token });
                }
            }

            // Return an error if authentication fails
            return Unauthorized(new { Message = "Invalid login attempt." });
        }
        private string GenerateJwtToken(RegisterModel user)
        {
            Console.WriteLine($"JWT Key: {_configuration["Jwt:Key"]}");

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            
        };
            foreach (var role in user.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role,role ));
            }

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Issuer"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        [HttpGet("protected")]
        [TypeFilter(typeof(RoleAuthorizationFilter))]

        public IActionResult ProtectedEndpoint()
        {
            return Ok("this is protected endpoint");   
           
        }

        [HttpGet("hi")]

        public IActionResult Protected()
        {
            Console.WriteLine("Authorized");
            return Ok("HI from .net");
        }
        [HttpPost]
        public async Task<IActionResult> ChangeUserRole(RegisterModel registerModel)
        {
            var user = await _userManager.FindByEmailAsync(registerModel.Email);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            // Remove existing roles
            var existingRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in existingRoles)
            {
                await _userManager.RemoveFromRoleAsync(user, role);
            }

            // Add new role
            await _userManager.AddToRoleAsync(user, registerModel.Role);

            // Redirect back to the manage users page or any other relevant page
            return Ok(new { Message = "Roles Updated Successfully!" });
        }
        [HttpPost]
        [Route("api/account/forgotpassword")]
        public async Task<IActionResult> ForgotPassword(ForgotPassword model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null /*|| !(await _userManager.IsEmailConfirmedAsync(user))*/)
            {
                // Don't reveal that the user does not exist or is not confirmed
                return Ok(); // Or return a success response without revealing details
            }

            // Generate password reset token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Send the token to the user via email (implementation not provided here)

            return Ok(new {_token = token}); // Or return a success response
        }
        [HttpPost]
        [Route("api/account/resetpassword")]
        public async Task<IActionResult> ResetPassword(ForgotPassword model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return Ok(); // Or return a success response without revealing details
            }

            // Reset password using the token
            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
            {
                return Ok(); // Or return a success response
            }
            else
            {
                return BadRequest(result.Errors);
            }
        }
        [HttpPost("SendEmail")]
        public async Task<IActionResult> SendEmailAsync([FromBody] SendEmailRequest request)
        {
            var email = new MimeMessage();
            email.From.Add(new MailboxAddress("Khush Bhadrecha", "khushbhadrecha02@gmail.com"));
            email.To.Add(new MailboxAddress("Jimmy Pot", request.Email));
            email.Subject = "Email verification for your registration attempt";
            email.Body = new TextPart("Html")
            {
                Text = $"Please confirm your account by <a href='{request.HtmlMessage}'>clicking here</a>."
            };

            using (var smtp = new SmtpClient())
            {
                smtp.Connect("smtp.gmail.com", 587, false);
                smtp.Authenticate("khushbhadrecha02@gmail.com", "evasrxlbzwmuogsr");
                await smtp.SendAsync(email);
                smtp.Disconnect(true);
            }

            return Ok(new { message = "Email confirmed successfully" });
        }
        [HttpPost("ConfirmEmail")]
        
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmail request)
        {
            var user = await _userManager.FindByIdAsync(request.userID);
            if (user == null)
            {
                // User not found
                return Ok(new { error = "User not found" });
            }

            var result = await _userManager.ConfirmEmailAsync(user, request.token);
            if (result.Succeeded)
            {
                // Email confirmed successfully
                return Ok(new { message = "Email confirmed successfully" });
            }
            else
            {
                // Email confirmation failed
                return BadRequest(new { errors = result.Errors });
            }
        }
        [HttpPost("AddBooksDetails")]
        public async Task<ActionResult<Book>> AddBookAsync(Book book)
        {
            try
            {
                var addedBook = await _bookService.AddBookAsync(book);
                return Ok(addedBook);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
        [HttpGet("{username}")]
        public async Task<ActionResult<string>> GetUserIdByUsername(string username)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(username);
                if (user == null)
                {
                    return NotFound("User not found");
                }

                return Ok(user.Id);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
        [HttpGet("user/{userId}")]
        public async Task<ActionResult<IEnumerable<Book>>> GetBooksByUserId(string userId)
        {
            try
            {
                var books = await identityFramewrokUsingApiContext.Books
                    .Where(b => b.UserId == userId)
                    .ToListAsync();

                if (books == null || !books.Any())
                {
                    return NotFound("No books found for this user");
                }

                return Ok(books);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
        [HttpDelete("{bookId}")]
        public async Task<ActionResult> DeleteBookAsync(int bookId)
        {
            try
            {
                var book = await identityFramewrokUsingApiContext.Books.FindAsync(bookId);
                if (book == null)
                {
                    return NotFound("Book not found");
                }

                identityFramewrokUsingApiContext.Books.Remove(book);
                await identityFramewrokUsingApiContext.SaveChangesAsync();

                return NoContent();
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }






    }
}
