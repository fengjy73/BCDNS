package org.bcdns.credential;

import org.junit.Test;
import static com.alibaba.druid.filter.config.ConfigTools.encrypt;
import static com.alibaba.druid.filter.config.ConfigTools.genKeyPair;

public class ConfigToolsTest {
    @Test
    public void testPassword() throws Exception {
        String password = "Mychain123!@#";
        String[] arr = genKeyPair(512);
        System.out.println("password:" + password);
        System.out.println("privateKey:" + arr[0]);
        System.out.println("publicKey:" + arr[1]);
        System.out.println("password:" + encrypt(arr[0], password));
    }

    @Test
    public void testPassword1() throws Exception {
        String password = "priSPKfJPS11hGWCnHHzgwfVyL4RbMKQGqfLpX5JZYuE2bDbbx";
        String privateKey = "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAg0GtzkzxbbvRmWRiIplqXR29lp2CrxphEFRmMH0RQZHwUSkeBasTclZlwq5NQ7zAvv6FMt8euliche+aHAlKfQIDAQABAkAfaee0GTwq/CmU4a6PA1KuiICofHgbel/CrcBrWHN50p++b3D9mf1bAPsQL9HUgYSAdbWsZRktM+8fZlO/m3YtAiEA2YVXknSVfOmqwvABwVnvSHF26ucRjw/fPztrKvKuwe8CIQCaecSpI+lK6tJIqUTKpav2TcmSQ6mQN0a/Jfdujwg2UwIgBRMoVOFlb3GgK0YgNFudyonjJV3Yuga7xaTkPi9FRn8CID5PyCiCN+TkfBabUQh9c7RTBHBfotJtubf5VKngQGvJAiBitrbI7gp9u+qSOyACHh6zFZP5BCyfJGKEug5JzGQeMg==";
        System.out.println("password:" + encrypt(privateKey, password));
    }
}
