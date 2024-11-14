using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TestAPIwithJWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecuredController : Controller
    {
        [HttpGet]
        [Authorize]
        public IActionResult GetData()
        {

            return Ok("Hello Form Get Data");
        }
    }
}
