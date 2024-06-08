using Identityframeworkwithapi.Models;

namespace Identityframeworkwithapi.Services
{
    public interface IBookService
    {
        Task<Book> AddBookAsync(Book book);

    }
    public class BookService : IBookService
    {
        private readonly IdentityFramewrokUsingApiContext _dbContext;

        public BookService(IdentityFramewrokUsingApiContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<Book> AddBookAsync(Book book)
        {
            
            _dbContext.Books.Add(book);
            await _dbContext.SaveChangesAsync();
            return book;
        }
    }
}
