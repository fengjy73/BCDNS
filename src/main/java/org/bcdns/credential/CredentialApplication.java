package org.bcdns.credential;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/*@EnableFeignClients
@Configuration*/
@SpringBootApplication(scanBasePackages = "org.bcdns.credential")
//@MapperScan(basePackages = {"com.alipay.antchain.web3service.repository.mapper"})
public class CredentialApplication {
    public static void main(String[] args) {
        SpringApplication.run(CredentialApplication.class, args);
    }
}
