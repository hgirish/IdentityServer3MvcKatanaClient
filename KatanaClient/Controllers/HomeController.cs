using System.Web;
using System.Web.Mvc;

namespace KatanaClient.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult Claims()
        {
            ViewBag.Message = "Claims";
            return View();
        }

        public ActionResult Signout()
        {
            // also possible to pass post logout redirect url via properties
            //var properties = new AuthenticationProperties()
            //{
            //    RedirectUri = "https://localhost:44302/"
            //};
            //Request.GetOwinContext().Authentication.SignOut(properties);

            Request.GetOwinContext().Authentication.SignOut();
            return Redirect("/");
        }
        [Authorize(Roles = "Admin")]
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}