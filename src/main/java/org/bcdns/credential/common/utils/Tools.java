package org.bcdns.credential.common.utils;

import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.regex.Pattern;

public class Tools {
    public Tools() {
    }

    public static boolean isNull(Object obj) {
        return obj == null || isBlank(obj.toString()) || "null".equals(obj);
    }

    public static boolean isBlank(String str) {
        int strLen;
        if (str != null && (strLen = str.length()) != 0) {
            for(int i = 0; i < strLen; ++i) {
                if (!Character.isWhitespace(str.charAt(i))) {
                    return false;
                }
            }

            return true;
        } else {
            return true;
        }
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];

        for(int i = 0; i < len; i += 2) {
            data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }

        return data;
    }

    public static String bytesToHex(byte[] raw) {
        if (raw == null) {
            return null;
        } else {
            StringBuilder hex = new StringBuilder(2 * raw.length);
            byte[] var2 = raw;
            int var3 = raw.length;

            for(int var4 = 0; var4 < var3; ++var4) {
                byte b = var2[var4];
                hex.append(Character.forDigit((b & 240) >> 4, 16)).append(Character.forDigit(b & 15, 16));
            }

            return hex.toString();
        }
    }
}
