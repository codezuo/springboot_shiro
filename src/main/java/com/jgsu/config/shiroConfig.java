package com.jgsu.config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/*
 * shiro的配置类
 * */
@Configuration   //表名该类为配置类
public class shiroConfig {
    /*
     * 1.创建ShiroFilterFactoryBean
     * */
    @Bean("filterFactoryBean")
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier(value = "securityManager") DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        //设置安全管理器(defaultWebSecurityManager)
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        /*
         ****** shiro的内置过滤器****
         * anon ：无参，表示可匿名访问
         * authc ：无参，表示需要认证才能访问
         * authcBasic ：无参，表示需要httpBasic认证才能访问
         * user ：表示用户不一定需要通过认证，只要曾被 Shiro 记住过登录状态(RememberMe)就可以正常发起 /home 请求
         * perms[admin:edit]：表示用户必需已通过认证，并拥有 admin:edit 权限才可以正常发起 /edit 请求
         * roles[admin] ：表示用户必需已通过认证，并拥有 admin 角色才可以正常发起 /admin 请求
         * */
        Map<String, String> filters = new LinkedHashMap();  //顺序的Map
        filters.put("/login", "anon");
        filters.put("/testThymeleaf", "anon");//anon ：无参，表示可匿名访问(无需权限)，没有设置的表示默认无需权限访问
       // filters.put("/add", "authc");//authc,使得/add需要授权才能访问
        //授权过滤器
        //user:update为授权字符串必须与UserRealm中的 info.addStringPermission("user:update");一致
        filters.put("/update","perms[user:update]");//表示用户必需已通过认证，并拥有 user:update 权限才可以正常发起 /update 请求
        filters.put("/add","perms[user:add]");
        shiroFilterFactoryBean.setLoginUrl("/toLogin");   //设置需要授权的路径经拦截后跳转的路径
        shiroFilterFactoryBean.setUnauthorizedUrl("/unAuth");  //跳转到未授权提示页面
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filters);
        return shiroFilterFactoryBean;
    }

    /*
     * 2.创建DefaultWebSecurityManager
     * SecurityManager是Shiro的心脏，所有具体的交互都通过SecurityManager进行控制，它管理着所有Subject、且负责进行认证和授权、及会话、缓存的管理。
     * */
    @Bean(name = "securityManager")
    public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier(value = "userRealm") UserRealm userRealm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(userRealm);
        return securityManager;
    }

    /*
     *引入自定义的Realm
     * */
    @Bean(name = "userRealm")   //将其添加到spring容器中
    public UserRealm getUserRealm() {
        return new UserRealm();
    }

    /*
    * 配置shiroDailect模块整合thymeleaf与shiro，用以实现不同权限用户模块的查看
    * */
    @Bean
    public ShiroDialect getShiroDialect(){
        return new ShiroDialect();
    }

}
