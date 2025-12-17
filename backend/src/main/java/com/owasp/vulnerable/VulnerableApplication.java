package com.owasp.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * 
 * 請勿在生產環境中部署！
 */
@SpringBootApplication
@EntityScan(basePackages = {"com.owasp.common.model", "com.owasp.common.entity"})
@EnableJpaRepositories(basePackages = "com.owasp.common.repository")
public class VulnerableApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }

}
