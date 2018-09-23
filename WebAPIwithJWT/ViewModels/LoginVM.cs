using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebAPIwithJWT.ViewModels
{
    public class LoginVM
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}