using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Authentication_with_JWT_and_OAuth.AuthService.Controllers
{
    [ApiController]
    [Route("admin")]
    [Authorize(Roles = "ADMIN")]
    public class AdminController : ControllerBase
    {


        [HttpGet("ping")]
        public IActionResult Ping()
        {
            return Ok("✅ Admin-access bekräftad!");
        }

        [HttpGet("users")]
        [Authorize(Roles = "ADMIN")]
        public async Task<IActionResult> GetAllUsers([FromServices] UserManager<ApplicationUser.ApplicationUser> userManager)
        {
            var users = userManager.Users.ToList();

            var result = new List<object>();

            foreach (var user in users)
            {
                var roles = await userManager.GetRolesAsync(user);

                result.Add(new
                {
                    id = user.Id,
                    email = user.Email,
                    roles = roles
                });
            }

            return Ok(result);
        }


        [HttpDelete("users/{id}")]
        [Authorize(Roles = "ADMIN")]
        public async Task<IActionResult> DeleteUser(string id, [FromServices] UserManager<ApplicationUser.ApplicationUser> userManager)
        {
            var user = await userManager.FindByIdAsync(id);

            if (user == null)
                return NotFound("Användare hittades inte.");

            var result = await userManager.DeleteAsync(user);

            if (!result.Succeeded)
                return BadRequest("Det gick inte att ta bort användaren.");

            return Ok($"Användare med ID {id} togs bort.");
        }



    }
}