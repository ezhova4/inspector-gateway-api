package ru.clevertec.inspector.gatewayregistry;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

@EnableZuulProxy
@EnableEurekaServer
@SpringBootApplication
public class GatewayRegistryApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayRegistryApplication.class, args);
    }

}
