package com.jgsu;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.jgsu.dao")
public class Shiro04Application {

    public static void main(String[] args) {
        SpringApplication.run(Shiro04Application.class, args);
    }

}
