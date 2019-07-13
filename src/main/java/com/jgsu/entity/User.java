package com.jgsu.entity;

import lombok.Data;

@Data
public class User {
    private Integer uid;
    private String username;
    private String password;
    private String perms;   //用户权限字段
}
