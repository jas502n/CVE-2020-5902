package org.apache.jsp.tmui.locallb.workspace;

import com.f5.tmui.locallb.handler.workspace.WorkspaceUtils;
import com.f5.util.F5Properties;
import com.f5.util.User;
import com.f5.util.UsernameHolder;
import com.f5.util.WebUtils;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.el.ExpressionFactory;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.jsp.JspFactory;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.SkipPageException;
import org.apache.jasper.runtime.HttpJspBase;
import org.apache.jasper.runtime.InstanceManagerFactory;
import org.apache.jasper.runtime.JspSourceDependent;
import org.apache.tomcat.InstanceManager;
import org.json.simple.JSONObject;

public final class fileSave_jsp extends HttpJspBase implements JspSourceDependent {
   private static final JspFactory _jspxFactory = JspFactory.getDefaultFactory();
   private static Map _jspx_dependants;
   private volatile ExpressionFactory _el_expressionfactory;
   private volatile InstanceManager _jsp_instancemanager;

   public Map getDependants() {
      return _jspx_dependants;
   }

   public ExpressionFactory _jsp_getExpressionFactory() {
      if (this._el_expressionfactory == null) {
         synchronized(this) {
            if (this._el_expressionfactory == null) {
               this._el_expressionfactory = _jspxFactory.getJspApplicationContext(this.getServletConfig().getServletContext()).getExpressionFactory();
            }
         }
      }

      return this._el_expressionfactory;
   }

   public InstanceManager _jsp_getInstanceManager() {
      if (this._jsp_instancemanager == null) {
         synchronized(this) {
            if (this._jsp_instancemanager == null) {
               this._jsp_instancemanager = InstanceManagerFactory.getInstanceManager(this.getServletConfig());
            }
         }
      }

      return this._jsp_instancemanager;
   }

   public void _jspInit() {
   }

   public void _jspDestroy() {
   }

   public void _jspService(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
      HttpSession session = null;
      JspWriter out = null;
      JspWriter _jspx_out = null;
      PageContext _jspx_page_context = null;

      try {
         response.setContentType("text/html");
         PageContext pageContext = _jspxFactory.getPageContext(this, request, response, (String)null, true, 8192, true);
         _jspx_page_context = pageContext;
         ServletContext application = pageContext.getServletContext();
         ServletConfig config = pageContext.getServletConfig();
         session = pageContext.getSession();
         out = pageContext.getOut();
         out.write("\n\n\n\n\n\n\n\n\n\n\n");
         String fileName = WebUtils.getProperty(request, "fileName");
         String saveResult = "";
         String username = request.getRemoteUser();
         Enumeration headerNames = request.getHeaderNames();
         Map headers = new HashMap();
         if (username == null) {
            username = F5Properties.getApplicationString("auth.override_user");
         }

         while(headerNames.hasMoreElements()) {
            String headerName = (String)headerNames.nextElement();
            headers.put(headerName, request.getHeader(headerName));
         }

         User user = new User(username, headers);
         UsernameHolder.setUser(user);

         try {
            if (!WorkspaceUtils.isFileWhitelisted(fileName)) {
               throw new IllegalAccessException("Forbidden to access file " + fileName);
            }

            if (!WorkspaceUtils.userCanAccessPartition(user, fileName, true)) {
               throw new IllegalAccessException("Forbidden to access file " + fileName);
            }

            JSONObject resultObject = WorkspaceUtils.saveFile(request);
            saveResult = resultObject.toString();
         } catch (IOException var25) {
            throw var25;
         } catch (IllegalAccessException var26) {
            throw var26;
         }

         out.write(10);
         out.write(10);
         out.print(saveResult);
         out.write(10);
      } catch (Throwable var27) {
         if (!(var27 instanceof SkipPageException)) {
            out = (JspWriter)_jspx_out;
            if (_jspx_out != null && ((JspWriter)_jspx_out).getBufferSize() != 0) {
               try {
                  if (response.isCommitted()) {
                     out.flush();
                  } else {
                     out.clearBuffer();
                  }
               } catch (IOException var24) {
               }
            }

            if (_jspx_page_context == null) {
               throw new ServletException(var27);
            }

            _jspx_page_context.handlePageException(var27);
         }
      } finally {
         _jspxFactory.releasePageContext(_jspx_page_context);
      }

   }
}
