package org.bcdns.credential.common.utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64UrlUtil {

    public static String formatEncode(String s){
        s = s.split("=")[0]; // Remove any trailing '='s
        s = s.replace('+', '-'); // 62nd char of encoding
        s = s.replace('/', '_'); // 63rd char of encoding
        return s;
    }

    static String formatDecode(String arg)
    {
        String s = arg;
        s = s.replace('-', '+'); // 62nd char of encoding
        s = s.replace('_', '/'); // 63rd char of encoding
        switch (s.length() % 4) // Pad with trailing '='s
        {
            case 0: break; // No pad chars in this case
            case 2: s += "=="; break; // Two pad chars
            case 3: s += "="; break; // One pad char
            default: return null;
        }
        return s; // Standard base64 decoder
    }


    //base64url Encoding without Padding
    public static String base64Encode(String msg){
        return base64Encode(msg.getBytes(StandardCharsets.UTF_8));
    }

    public static String base64Encode(byte[] msg){
        return formatEncode(Base64.getEncoder().encodeToString(msg));
    }

    public static String base64UrlDecode2String(String str){
        return new String(base64Decode(str),StandardCharsets.UTF_8);
    }

    public static byte[] base64Decode(String str){
        return Base64.getDecoder().decode(formatDecode(str));
    }

}