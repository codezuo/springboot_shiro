package com.jgsu.service;

import com.jgsu.entity.User;

public interface UserService {
    User findByUserName(String username);
    User findById(Integer uid);
}
