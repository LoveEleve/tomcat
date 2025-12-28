package com.debug;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class TestServlet extends HttpServlet {

    @Override
    public void init() throws ServletException {
        System.out.println("[TestServlet] init() 被调用");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        System.out.println("[TestServlet] doGet() 被调用");

        resp.setContentType("text/html;charset=UTF-8");
        PrintWriter out = resp.getWriter();
        out.println("<html><body>");
        out.println("<h1>TestServlet - doGet</h1>");
        out.println("<p>RequestURI: " + req.getRequestURI() + "</p>");
        out.println("<p>SessionId: " + req.getSession().getId() + "</p>");
        out.println("</body></html>");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        System.out.println("[TestServlet] doPost() 被调用");
        doGet(req, resp);
    }

    @Override
    public void destroy() {
        System.out.println("[TestServlet] destroy() 被调用");
    }
}
