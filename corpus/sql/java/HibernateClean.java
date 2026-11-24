import java.util.List;
import javax.servlet.http.*;
import org.hibernate.Session;
import org.hibernate.query.Query;

public class HibernateClean extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String name = req.getParameter("name");
    Session s = HibernateUtil.getSessionFactory().openSession();
    Query<?> q = s.createQuery("FROM User WHERE name = :name", User.class);
    q.setParameter("name", name);
    res.getWriter().print(q.list().size());
  }
}
