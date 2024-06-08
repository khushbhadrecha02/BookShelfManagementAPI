using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Identityframeworkwithapi.Models
{
    public partial class IdentityFramewrokUsingApiContext : DbContext
    {
        public IdentityFramewrokUsingApiContext()
        {
        }

        public IdentityFramewrokUsingApiContext(DbContextOptions<IdentityFramewrokUsingApiContext> options)
            : base(options)
        {
        }

        public virtual DbSet<Book> Books { get; set; } = null!;

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {

            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Book>(entity =>
            {
                entity.Property(e => e.BookId).HasColumnName("book_id");

                entity.Property(e => e.Author)
                    .HasMaxLength(255)
                    .HasColumnName("author");

                

                entity.Property(e => e.Genre)
                    .HasMaxLength(100)
                    .HasColumnName("genre");

                entity.Property(e => e.Isbn)
                    .HasMaxLength(20)
                    .HasColumnName("isbn");


                entity.Property(e => e.Title)
                    .HasMaxLength(255)
                    .HasColumnName("title");



                entity.Property(e => e.UserId)
                    .HasMaxLength(450)
                    .HasColumnName("user_id");
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
