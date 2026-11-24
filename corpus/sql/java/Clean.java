import java.sql.*;
import javax.servlet.http.*;

public class Clean extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String name = req.getParameter("name");
    Connection c = DriverManager.getConnection("jdbc:mysql://localhost/shop", "shop", "secret");
    PreparedStatement s = c.prepareStatement("SELECT id, name FROM users WHERE name = ?");
    s.setString(1, name);
    ResultSet r = s.executeQuery();
    while (r.next()) res.getWriter().print(r.getString("name"));
  }
}
