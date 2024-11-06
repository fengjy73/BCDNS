package org.bcdns.credential;

import com.alibaba.druid.filter.config.ConfigTools;
import org.junit.Test;

import static com.alibaba.druid.filter.config.ConfigTools.*;

public class ConfigToolsTest {
    @Test
    public void testCreateKeyPair() throws Exception {
        String[] arr = genKeyPair(512);
        System.out.println("privateKey:" + arr[0]);
        System.out.println("publicKey:" + arr[1]);
    }

    @Test
    public void testEncrypt() throws Exception {
        String password = "priSPKt9wkwEwc4suujrhf5Rxwdpxryx5QjBkuQyHjejKAwUBm";
        String privateKey = "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAunLtL3wVMCmLCj9TrMEkAYLIYu26pk2FGYkKg1wKnufxeToMOGgFa3B44b2/uE+ojlg3/q07maQW36cPEf6SRwIDAQABAkBoBb63A29+026zZOl2NLu17BWIvEGqjw13VbH739o9FQ5R20jI10Ypq83Gsg7eLkTXTlkSQ4W1UNJZCM9//xQBAiEA7VKb/g6wve1WYeDbsWcCHbFV06mBtvwCHqNWzQyDvYECIQDJH1pKg6t3xIzqw9TwNbWXJZPoJrRTdbwhHGSWFr3DxwIhAILYSgMvzEha44aBd/7+YQ9H558UVN0zYmPMAJ566OOBAiBFR26Dwm1bOTJNYB3GjMm7ge88BbESGrkuMqiXZsgBWwIhALYOVdvMW+BWLC+9WMwz4TwnpmJcxSAIPGP3ijX2Et9e";
        System.out.println("password:" + encrypt(privateKey, password));
    }
}
