using System.Data.SqlClient;
using System.Web;
using System.Web.Mvc;

public class OrdersController : Controller {
  public ActionResult Index() {
    string user = Request.QueryString["user"];
    var conn = new SqlConnection("Server=.;Database=shop;Trusted_Connection=True;");
    var cmd = new SqlCommand("SELECT id, total FROM orders WHERE user = '" + user + "'", conn); // MACSEC-SQLI
    return Content(cmd.ExecuteScalar()?.ToString() ?? "");
  }
}
