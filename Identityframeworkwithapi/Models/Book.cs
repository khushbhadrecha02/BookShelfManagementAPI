using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Identityframeworkwithapi.Models
{
    public partial class Book
    {
        public int BookId { get; set; }
        
        public string UserId { get; set; } = null!;
        [Required]
        public string Title { get; set; } = null!;
        [Required]
        public string? Author { get; set; }
        [Required]
        public string? Genre { get; set; }
        
        public string? Isbn { get; set; }
        }
    }

