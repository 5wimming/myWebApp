package com.orz;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.swing.*;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import org.apache.commons.collections.*;

//@WebServlet(name = "Servlet")
public class MyDemo extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<h1>GET: all is well</h1>");
    }
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<h1>POST: all is well</h1>");
        try{
            ServletInputStream inputStream = request.getInputStream();
            ObjectInputStream ois = new ObjectInputStream(inputStream);
            ois.readObject();
        }
        catch(Exception e){
            e.printStackTrace();
            out.println(e.toString());
        }
    }
}
