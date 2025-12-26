package com.debug;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
/**
 * @Classname TestServlet
 * @Date 12/15/25
 * @Created by ywj
 */
public class TestServlet extends HttpServlet
{

    @Override
    public void init() throws ServletException {
        super.init();
        System.out.println("=== TestServlet 初始化 ===");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {

        System.out.println("\n========== 请求到达 TestServlet ==========");
        System.out.println("请求URI: " + req.getRequestURI());
        System.out.println("请求URL: " + req.getRequestURL());
        System.out.println("Context Path: " + req.getContextPath());
        System.out.println("Servlet Path: " + req.getServletPath());

        // 打印完整调用栈，追踪请求路径
        System.out.println("\n=== 完整调用栈 ===");
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        for (int i = 0; i < Math.min(stackTrace.length, 30); i++) {
            StackTraceElement element = stackTrace[i];
            if (element.getClassName().contains("org.apache.catalina") ||
                element.getClassName().contains("org.apache.coyote") ||
                element.getClassName().contains("com.debug")) {
                System.out.println("  -> " + element.getClassName() + "." +
                    element.getMethodName() + "(" +
                    element.getFileName() + ":" +
                    element.getLineNumber() + ")");
            }
        }
        System.out.println("==========================================\n");

        // 返回响应
        resp.setContentType("text/html;charset=UTF-8");
        PrintWriter out = resp.getWriter();
        out.println("<html>");
        out.println("<head><title>Tomcat Debug Test</title></head>");
        out.println("<body>");
        out.println("<h1>请求成功到达Servlet！</h1>");
        out.println("<p>请查看控制台输出的调用栈信息</p>");
        out.println("<p>Request URI: " + req.getRequestURI() + "</p>");
        out.println("<p>Context Path: " + req.getContextPath() + "</p>");
        out.println("</body>");
        out.println("</html>");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
        doGet(req, resp);
    }
}
