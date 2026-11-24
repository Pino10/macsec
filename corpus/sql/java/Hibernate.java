import java.util.List;
import javax.servlet.http.*;
import org.hibernate.Session;

public class Hibernate extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String name = req.getParameter("name");
    Session s = HibernateUtil.getSessionFactory().openSession();
    List<?> rows = s.createQuery("FROM User WHERE name = '" + name + "'").list(); // MACSEC-SQLI
    res.getWriter().print(rows.size());
  }
}
