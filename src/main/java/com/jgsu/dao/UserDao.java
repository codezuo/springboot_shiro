package com.jgsu.dao;

import com.jgsu.entity.User;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDao {
    @Select("select * from user where username = #{username}")
     User findByUserName(String username);
    //根据uid查数据
    @Select("select * from user where uid = #{uid}")
    User findById(Integer uid);
}
