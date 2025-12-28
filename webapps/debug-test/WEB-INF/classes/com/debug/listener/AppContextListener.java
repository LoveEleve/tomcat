package com.debug.listener;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class AppContextListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        System.out.println("[AppContextListener] contextInitialized() - 应用启动");
        System.out.println("  ContextPath: " + sce.getServletContext().getContextPath());
        System.out.println("  ServerInfo: " + sce.getServletContext().getServerInfo());
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        System.out.println("[AppContextListener] contextDestroyed() - 应用关闭");
    }
}
