using System;
using System.Web.Mvc;

namespace KatanaClient
{
    public class CustomRequireHttpsFilter : RequireHttpsAttribute
    {
        protected override void HandleNonHttpsRequest(AuthorizationContext filterContext)
        {
            // The base only redirects GET, but we added HEAD as well. This avoids exceptions for bots crawling using HEAD.
            // The other requests will throw an exception to ensure the correct verbs are used. 
            // We fall back to the base method as the mvc exceptions are marked as internal. 

            if (!String.Equals(filterContext.HttpContext.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase)
                && !String.Equals(filterContext.HttpContext.Request.HttpMethod, "HEAD", StringComparison.OrdinalIgnoreCase))
            {
                base.HandleNonHttpsRequest(filterContext);
            }

            // Redirect to HTTPS version of page
            // We updated this to redirect using 301 (permanent) instead of 302 (temporary).
            string url = "https://" + filterContext.HttpContext.Request.Url.Host + filterContext.HttpContext.Request.RawUrl;

            if (string.Equals(filterContext.HttpContext.Request.Url.Host, "localhost", StringComparison.OrdinalIgnoreCase))
            {
                // For localhost requests, default to IISExpress https default port (44300)
                url = "https://" + filterContext.HttpContext.Request.Url.Host + ":44302" + filterContext.HttpContext.Request.RawUrl;
            }

            filterContext.Result = new RedirectResult(url, true);
        }
    }
}