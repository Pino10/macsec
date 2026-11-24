import java.sql.*;
import javax.servlet.http.*;

public class Vulnerable extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String name = req.getParameter("name");
    Connection c = DriverManager.getConnection("jdbc:mysql://localhost/shop", "shop", "secret");
    Statement s = c.createStatement();
    ResultSet r = s.executeQuery("SELECT id, name FROM users WHERE name = '" + name + "'");
    while (r.next()) res.getWriter().print(r.getString("name"));
  }
}
