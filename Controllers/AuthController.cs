using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NuGet.Common;
using TestAPIwithJWTAuthentication.Models;
using TestAPIwithJWTAuthentication.Services;

namespace TestAPIwithJWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService _authService) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            // تحقق من صحة نموذج البيانات
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // محاولة تسجيل المستخدم الجديد باستخدام خدمة المصادقة
            var result = await _authService.RegisterAsync(model);

            // إذا كانت المصادقة غير ناجحة، إرجاع رسالة خطأ
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

            // إذا كانت المصادقة ناجحة، إرجاع النموذج المصادق عليه
            return Ok(result);
            //return Ok(new { token = result.Token, expiresOn = result.ExpiresOn });
        }


        [HttpPost("addrole")]
        public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
        {
            // تحقق من صحة نموذج البيانات
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // محاولة تسجيل المستخدم الجديد باستخدام خدمة المصادقة
            var result = await _authService.AddRoleAsync(model);

            // إذا كانت المصادقة غير ناجحة، إرجاع رسالة خطأ
            if (string.IsNullOrEmpty(result))
                return BadRequest(result);

            // إذا كانت المصادقة ناجحة، إرجاع النموذج المصادق عليه
            return Ok(model);
        }

        [HttpPost("token")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            // تحقق من صحة نموذج البيانات
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // محاولة تسجيل المستخدم الجديد باستخدام خدمة المصادقة
            var result = await _authService.GetTokenAsync(model);

            // إذا كانت المصادقة غير ناجحة، إرجاع رسالة خطأ
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            if (!string.IsNullOrEmpty(result.RefreshToken))
                SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

            // إذا كانت المصادقة ناجحة، إرجاع النموذج المصادق عليه
            return Ok(result);
        }

        [HttpGet("refreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            var result = await _authService.RefreshTokenAsync(refreshToken);

            if (!result.IsAuthenticated)
                return BadRequest(result);

            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

            return Ok(result);

        }

        [HttpPost("revokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeToken model)
        {
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest("Token is required! ");

            var result = await _authService.RevokeTokenAsync(token);

            if (!result)
                return BadRequest("Token is invalid! ");


            return Ok();

        }

        private void SetRefreshTokenInCookie(string refreshToken, DateTime expires)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expires.ToLocalTime()
            };

            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }
    }
}
