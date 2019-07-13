package com.jgsu.config;

import com.jgsu.entity.User;
import com.jgsu.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;

/*
 * 自定义一个Realm，
 * */
public class UserRealm extends AuthorizingRealm {
    /*该方法为授权作用*/
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("该方法为授权作用");
        //给资源进行授权
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        //添加授权资源的字符串(此方法不灵活，不能直接从数据库中获取权限)
        //info.addStringPermission("user:update");
        //1.先获取用户
        Subject subject = SecurityUtils.getSubject();
        //获取的是User用户的值:User(uid=1, username=aaa, password=123, perms=user:add)
        User user = (User) subject.getPrincipal();
        //System.out.println("getPrincipal的值为:" + subject.getPrincipal());
        User id = userService.findById(user.getUid());
        info.addStringPermission(id.getPerms());
        return info;
    }

    @Autowired
    private UserService userService;

    /*该方法为认证作用，是主体（Subject）的身份认证信息*/
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("该方法为认证作用");
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        User user = userService.findByUserName(token.getUsername());
        if (user == null) {//如果用户名存在，则报错
            return null;
        }
        //第一个取值(user)为principal的值，对应上面的subject.getPrincipal();
        return new SimpleAuthenticationInfo(user, user.getPassword(), "");  //第三个字段是realm，即当前realm的名称。
    }
}
