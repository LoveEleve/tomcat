package com.debug.filter;

import javax.servlet.*;
import java.io.IOException;

public class EncodingFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("[EncodingFilter] init() 被调用");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("[EncodingFilter] doFilter() 开始");

        // 设置请求和响应编码
        request.setCharacterEncoding("UTF-8");
        response.setCharacterEncoding("UTF-8");

        // 继续过滤器链
        chain.doFilter(request, response);

        System.out.println("[EncodingFilter] doFilter() 结束");
    }

    @Override
    public void destroy() {
        System.out.println("[EncodingFilter] destroy() 被调用");
    }
}
