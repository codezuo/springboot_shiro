package com.jgsu.service.impl;

import com.jgsu.dao.UserDao;
import com.jgsu.entity.User;
import com.jgsu.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserDao userDao;
    @Override
    public User findByUserName(String username) {
        return userDao.findByUserName(username);
    }

    @Override
    public User findById(Integer uid) {
        return userDao.findById(uid);
    }
}
