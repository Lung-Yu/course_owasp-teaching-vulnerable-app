package com.owasp.log4shell;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 
 * 
 */
@SpringBootApplication
public class Log4ShellApplication {

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println(" WARNING: VULNERABLE APPLICATION");
        System.out.println("This application uses Log4j 2.14.1");
        System.out.println("FOR EDUCATIONAL PURPOSES ONLY!");
        System.out.println("========================================");
        SpringApplication.run(Log4ShellApplication.class, args);
    }
}
