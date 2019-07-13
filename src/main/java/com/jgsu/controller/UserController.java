package com.jgsu.controller;

import com.jgsu.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller

public class UserController {
    @Autowired
    UserService userService;
    /*
    * 测试Thymeleaf的功能
    * */
    @RequestMapping("/testThymeleaf")
    public String testThymeleaf(Model model){
       //将数据存入到model中
        model.addAttribute("name","hello Thymeleaf");
        //将存入的数据，返回至test.html显示
        return "test";

    }
    /*
    * add.html页面的跳转
    * */
    @RequestMapping("/add")
        public String add(){
        //返回的路径为:thymeleaf(默认加载)下的user下面的add.html
        System.out.println("add");
            return "/user/add";
        }

    /*
     * add.html页面的跳转
     * */
    @RequestMapping("/update")
    public String update() {
        //返回的路径为:thymeleaf(默认加载)下的user下面的update.html
        return "/user/update";
    }

    /*
        * login.html页面的跳转
        * */
    @RequestMapping("/toLogin")
    public String toLogin() {
        //返回的路径为:thymeleaf(默认加载)下的login.html
        System.out.println("toLogin");
        return "/login";
    }
    @RequestMapping("/unAuth")  //表示未被授权页面的路径
        public String unAuth() {
            //返回的路径为:thymeleaf(默认加载)下的login.html
            System.out.println("unAuth");
            return "/unAuth";
        }

/*
* 登录认证逻辑
* */
    @RequestMapping("/login")
    public String login(String username, String password,Model model) {
        System.out.println("login");
        System.out.println("username:"+username);
        System.out.println("password:"+password);
         //使用shiro进行登录验证
        //1.获取subject
        Subject subject = SecurityUtils.getSubject();
        //2.封装用户数据
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        try {
            //3.执行登录方法
            subject.login(token);
            return "redirect:/testThymeleaf";   //登录成功则重定向到/testThymeleaf页面
        } catch (UnknownAccountException e) {   //用户名错误
            //e.printStackTrace();
            model.addAttribute("msg", "用户名错误");
            return "login";
        } catch (IncorrectCredentialsException e) {  //密码错误
            //e.printStackTrace();
            model.addAttribute("msg", "密码错误");
            return "login";
        }

    }
}
