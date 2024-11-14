using System.ComponentModel.DataAnnotations;

namespace TestAPIwithJWTAuthentication.Models
{
    public class RegisterModel
    {
        [Required, StringLength(50)]
        public string FirstName { get; set; }

        [Required, StringLength(50)]
        public string LastName { get; set; }

        [Required, StringLength(150)]
        public string UserName { get; set; }

        [Required, StringLength(150)]
        public string Email { get; set; }

        [Required, StringLength(50)]
        public string Password { get; set; }
    }
}
